# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Ahmad Karawash
"""Tenant-scoped semantic cache.

Fixes vs. the original design:
  * Every entry carries tenant_id and a scope (agent + prompt version); a
    lookup can only match entries from the same tenant and scope. Without this
    tenant B gets tenant A's answers.
  * Entries expire (TTL), so stale answers age out.
  * The orchestrator only consults it where a prompt-keyed answer is safe
    (first message of a support conversation; never for coding).

Backends:
  * RediSearch (Redis Stack / Redis 8): HNSW vector index with a TAG filter.
    FLOAT32 by default; FLOAT16 halves memory on RediSearch 2.10+.
  * Fallback for plain Redis: brute-force cosine over the newest N entries of
    the tenant+scope. Fine for development; use RediSearch in production.

Embeddings: `HashingEmbedder` is a deterministic, offline, *lexical* embedder
(character n-gram hashing) — good enough to catch near-duplicates without an
API key. Pass any `embed(text) -> list[float]` for real semantic matching.
"""
from __future__ import annotations

import hashlib
import json
import logging
import re
import time
from typing import Callable

import numpy as np

log = logging.getLogger(__name__)


class HashingEmbedder:
    def __init__(self, dim: int = 384):
        self.dim = dim

    def __call__(self, text: str) -> list[float]:
        v = np.zeros(self.dim, dtype=np.float32)
        t = "  " + re.sub(r"\s+", " ", text.lower().strip()) + "  "
        for n in (3, 4):
            for i in range(len(t) - n + 1):
                h = int.from_bytes(hashlib.blake2b(t[i:i + n].encode(), digest_size=8).digest(), "little")
                v[h % self.dim] += 1.0 if (h >> 63) & 1 else -1.0
        norm = np.linalg.norm(v)
        return (v / norm if norm else v).tolist()


def _tag_escape(value: str) -> str:
    return re.sub(r"([^A-Za-z0-9_])", r"\\\1", value)


def _text(v) -> str:
    return v.decode("utf-8", errors="replace") if isinstance(v, (bytes, bytearray)) else str(v)


def first_hit(res) -> tuple[str, float] | None:
    """(response, distance) of the best FT.SEARCH hit, whatever shape the client
    returned: a `Result` object (RESP2, and redis-py 8's default legacy mode) or
    a RESP3 dict (`protocol=3`)."""
    docs = getattr(res, "docs", None)
    if docs is not None:
        if not docs:
            return None
        d = docs[0]
        return _text(d.response), float(_text(d.dist))
    if isinstance(res, dict):
        res = {_text(k): v for k, v in res.items()}
        results = res.get("results") or []
        if not results:
            return None
        item = {_text(k): v for k, v in results[0].items()}
        attrs = {_text(k): v for k, v in (item.get("extra_attributes") or {}).items()}
        return _text(attrs["response"]), float(_text(attrs["dist"]))
    raise TypeError(f"unexpected FT.SEARCH result type {type(res).__name__}")


class SemanticCache:
    INDEX = "idx:harnis_cache"
    PREFIX = "hcache:"

    def __init__(self, redis, embed: Callable[[str], list[float]] | None = None, *,
                 threshold: float = 0.08, ttl_seconds: int = 86400, vector_type: str = "FLOAT32",
                 fallback_max_entries: int = 500):
        self.r = redis
        self.embed = embed or HashingEmbedder()
        self.threshold = threshold  # cosine DISTANCE (0 = identical)
        self.ttl = ttl_seconds
        self.vector_type = vector_type
        self.fallback_max = fallback_max_entries
        self.dim = len(self.embed("probe"))
        self.vector_search = self._init_index()

    def _dtype(self):
        return np.float16 if self.vector_type == "FLOAT16" else np.float32

    def _init_index(self) -> bool:
        try:
            from redis.commands.search.field import TagField, TextField, VectorField
            try:
                from redis.commands.search.index_definition import IndexDefinition, IndexType
            except ImportError:  # redis-py < 6
                from redis.commands.search.indexDefinition import IndexDefinition, IndexType  # type: ignore
        except ImportError:
            return False
        import redis as redis_lib

        # RediSearch only indexes database 0 (and 2.10+ refuses FT.CREATE elsewhere);
        # an index found from another database would never see that database's keys.
        db = (getattr(self.r, "connection_pool", None) and self.r.connection_pool.connection_kwargs.get("db")) or 0
        if int(db) != 0:
            log.info("Redis database %s: RediSearch only indexes db 0; using brute-force cache fallback", db)
            return False
        try:
            self.r.ft(self.INDEX).info()
            return True
        except redis_lib.ConnectionError:
            raise  # Redis is down: say so, don't fall through to create_index
        except Exception as exc:
            if "unknown command" in str(exc).lower():
                log.info("RediSearch not available; using brute-force cache fallback")
                return False
        try:
            self.r.ft(self.INDEX).create_index(
                fields=[
                    TagField("tenant_id"), TagField("scope"), TextField("response"),
                    VectorField("embedding", "HNSW", {"TYPE": self.vector_type, "DIM": self.dim,
                                                       "DISTANCE_METRIC": "COSINE", "M": 16,
                                                       "EF_CONSTRUCTION": 200}),
                ],
                definition=IndexDefinition(prefix=[self.PREFIX], index_type=IndexType.HASH),
            )
            return True
        except Exception as exc:
            if "unknown command" in str(exc).lower():
                return False
            if "already exists" in str(exc).lower():
                return True
            raise

    def _vec(self, text: str) -> np.ndarray:
        return np.asarray(self.embed(text), dtype=np.float32)

    def lookup(self, tenant_id: str, scope: str, prompt: str) -> str | None:
        vec = self._vec(prompt)
        if self.vector_search:
            from redis.commands.search.query import Query

            q = (Query(f"(@tenant_id:{{{_tag_escape(tenant_id)}}} @scope:{{{_tag_escape(scope)}}})"
                       "=>[KNN 1 @embedding $v AS dist]")
                 .sort_by("dist").return_fields("response", "dist").dialect(2))
            try:
                res = self.r.ft(self.INDEX).search(q, query_params={"v": vec.astype(self._dtype()).tobytes()})
            except Exception as exc:
                # A FLUSHDB/FLUSHALL on any database drops every RediSearch index:
                # recreate it and treat this lookup as a miss.
                if "no such index" not in str(exc).lower():
                    raise
                log.warning("semantic cache index was dropped; recreating it")
                self._init_index()
                return None
            top = first_hit(res)
            if top is not None and top[1] <= self.threshold:
                return top[0]
            return None
        # Fallback: brute force over this tenant+scope only.
        zkey = f"hcache_idx:{tenant_id}:{scope}"
        best, best_dist = None, 2.0
        for key in self.r.zrevrange(zkey, 0, self.fallback_max - 1):
            raw = self.r.get(key)
            if raw is None:
                self.r.zrem(zkey, key)
                continue
            entry = json.loads(raw)
            other = np.asarray(entry["embedding"], dtype=np.float32)
            dist = 1.0 - float(np.dot(vec, other) / ((np.linalg.norm(vec) * np.linalg.norm(other)) or 1.0))
            if dist < best_dist:
                best, best_dist = entry["response"], dist
        return best if best is not None and best_dist <= self.threshold else None

    def clear_tenant(self, tenant_id: str) -> int:
        """Drop every cached answer of a tenant (user erasure, tenant deletion)."""
        n = 0
        for pattern in (f"{self.PREFIX}{tenant_id}:*", f"hcache_idx:{tenant_id}:*"):
            keys = list(self.r.scan_iter(pattern, count=500))
            for i in range(0, len(keys), 500):
                n += self.r.delete(*keys[i:i + 500])
        return n

    def store(self, tenant_id: str, scope: str, prompt: str, response: str) -> None:
        vec = self._vec(prompt)
        digest = hashlib.sha256(f"{tenant_id}|{scope}|{prompt}".encode()).hexdigest()[:24]
        key = f"{self.PREFIX}{tenant_id}:{digest}"
        if self.vector_search:
            self.r.hset(key, mapping={"tenant_id": tenant_id, "scope": scope, "response": response,
                                      "embedding": vec.astype(self._dtype()).tobytes()})
            self.r.expire(key, self.ttl)
            return
        self.r.set(key, json.dumps({"response": response, "embedding": vec.tolist()}), ex=self.ttl)
        zkey = f"hcache_idx:{tenant_id}:{scope}"
        self.r.zadd(zkey, {key: time.time()})
        self.r.zremrangebyrank(zkey, 0, -self.fallback_max - 1)
        self.r.expire(zkey, self.ttl)
