# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Ahmad Karawash
"""The semantic cache against real servers.

* HARNIS_TEST_VECTOR_REDIS_URL: a server with a search engine (Redis 8 or Redis
  Stack); the cache must use the vector index.
* HARNIS_TEST_PLAIN_REDIS_URL: a server without one (Valkey, plain Redis); the
  cache must fall back to brute-force search.

Both run in CI. Database 0: the search engine only indexes database 0, and the
test removes only the keys it wrote.
"""
import os
import uuid

import pytest

redis = pytest.importorskip("redis")

from harnis.cache import SemanticCache  # noqa: E402

CASES = [
    pytest.param(os.environ.get("HARNIS_TEST_VECTOR_REDIS_URL"), True, id="vector-index"),
    pytest.param(os.environ.get("HARNIS_TEST_PLAIN_REDIS_URL"), False, id="fallback"),
]


@pytest.mark.parametrize("url,expect_index", CASES)
def test_cache_hits_misses_and_tenant_isolation(url, expect_index):
    if not url:
        pytest.skip("server URL not set")
    r = redis.Redis.from_url(url)
    tenant_a, tenant_b = f"ta-{uuid.uuid4().hex[:8]}", f"tb-{uuid.uuid4().hex[:8]}"
    cache = SemanticCache(r, threshold=0.08)
    try:
        assert cache.vector_search is expect_index
        cache.store(tenant_a, "support:v1", "What are your opening hours?", "9 to 5, Monday to Friday.")
        # Same question, same tenant and scope: a hit (also with small wording changes).
        assert cache.lookup(tenant_a, "support:v1", "What are your opening hours?") == "9 to 5, Monday to Friday."
        assert cache.lookup(tenant_a, "support:v1", "what are your opening hours") == "9 to 5, Monday to Friday."
        # Another tenant, or another scope (agent / prompt version), never sees it.
        assert cache.lookup(tenant_b, "support:v1", "What are your opening hours?") is None
        assert cache.lookup(tenant_a, "support:v2", "What are your opening hours?") is None
        # An unrelated question is a miss.
        assert cache.lookup(tenant_a, "support:v1", "How do I reset my password?") is None
    finally:
        cache.clear_tenant(tenant_a)
        cache.clear_tenant(tenant_b)
