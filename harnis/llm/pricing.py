# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Ahmad Karawash
"""Token pricing, USD per million tokens.

Cost figures, per-turn cost budgets and tenant cost caps are only as good as
these prices, and provider prices change. So Harnis distinguishes:

* **confirmed prices**: entered by the operator, in PRICING_OVERRIDES (JSON) or
  a PRICING_FILE. `python tasks.py pricing` asks for them.
* **reference prices**: the table below, shipped with Harnis as a starting
  point. They may be out of date and are never treated as confirmed.

In production (ENV=production) the API refuses to start while a model it is
configured to call has no confirmed price. In development it logs a warning.
An unknown model is charged at UNKNOWN_MODEL_PRICE, deliberately high, so a
missing entry over-counts (and trips budgets) rather than under-counts.
"""
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Iterable

log = logging.getLogger(__name__)

# Reference values only (model -> (input $/MTok, output $/MTok)). Check them
# against the providers' pricing pages; confirm them with `python tasks.py pricing`.
REFERENCE_PRICES: dict[str, tuple[float, float]] = {
    "claude-sonnet-5-5": (3.00, 15.00),
    "claude-haiku-5-5": (1.00, 5.00),
    "claude-opus-5-5": (5.00, 25.00),
    "gpt-5.5": (2.50, 15.00),
    "gpt-5.4-mini": (0.40, 1.60),
    "gemini-3.8-flash": (0.30, 2.50),
    "gemini-3.5-flash-lite": (0.10, 0.40),
    # Bedrock ids: the regional prefix (us./eu./jp./apac./global.) is ignored on lookup.
    "amazon.nova-2-lite-v1:0": (0.30, 2.50),
    "amazon.nova-micro-v1:0": (0.035, 0.14),
}
FREE_MODELS = {"mock-main", "mock-fast"}  # the offline mock costs nothing
UNKNOWN_MODEL_PRICE = (15.00, 75.00)
PRICING_PAGES = {
    "anthropic": "https://www.anthropic.com/pricing",
    "openai": "https://openai.com/api/pricing/",
    "gemini": "https://ai.google.dev/pricing",
    "nova": "https://aws.amazon.com/bedrock/pricing/",
}

_BEDROCK_PREFIXES = ("us.", "eu.", "jp.", "apac.", "au.", "ca.", "us-gov.", "global.")
CONFIRMED: dict[str, tuple[float, float]] = {}


def _normalize(model: str) -> str:
    for prefix in _BEDROCK_PREFIXES:
        if model.startswith(prefix):
            return model[len(prefix):]
    return model


def parse_prices(data: Any, source: str) -> dict[str, tuple[float, float]]:
    """{"model": [input, output], ...} -> validated prices."""
    if not isinstance(data, dict):
        raise ValueError(f"{source}: expected a JSON object of model -> [input, output] USD per million tokens")
    out: dict[str, tuple[float, float]] = {}
    for model, value in data.items():
        if (not isinstance(value, (list, tuple)) or len(value) != 2
                or not all(isinstance(v, (int, float)) and v >= 0 for v in value)):
            raise ValueError(f"{source}: price for {model!r} must be [input, output], two non-negative numbers")
        out[str(model)] = (float(value[0]), float(value[1]))
    return out


def configure(overrides: dict[str, Any] | None = None, pricing_file: str = "") -> None:
    """Load the operator-confirmed prices (called at startup from settings)."""
    CONFIRMED.clear()
    if pricing_file:
        CONFIRMED.update(parse_prices(json.loads(Path(pricing_file).read_text(encoding="utf-8")), pricing_file))
    if overrides:
        CONFIRMED.update(parse_prices(overrides, "PRICING_OVERRIDES"))


def confirmed_price(model: str) -> tuple[float, float] | None:
    if model in FREE_MODELS:
        return (0.0, 0.0)
    return CONFIRMED.get(model) or CONFIRMED.get(_normalize(model))


def reference_price(model: str) -> tuple[float, float] | None:
    return REFERENCE_PRICES.get(model) or REFERENCE_PRICES.get(_normalize(model))


def price_for(model: str) -> tuple[float, float] | None:
    return confirmed_price(model) or reference_price(model)


def unconfirmed(models: Iterable[str]) -> list[str]:
    return sorted({m for m in models if confirmed_price(m) is None})


def cost_usd(model: str, input_tokens: int, output_tokens: int) -> float:
    price = price_for(model)
    if price is None:
        log.warning("no price configured for model %r; charging the conservative default", model)
        price = UNKNOWN_MODEL_PRICE
    return round(input_tokens / 1e6 * price[0] + output_tokens / 1e6 * price[1], 6)


def describe(models: Iterable[str]) -> list[dict[str, Any]]:
    """Pricing status for the admin API and console."""
    rows = []
    for m in sorted(set(models)):
        c, r = confirmed_price(m), reference_price(m)
        price = c or r
        rows.append({"model": m, "confirmed": c is not None,
                     "input_usd_per_mtok": price[0] if price else None,
                     "output_usd_per_mtok": price[1] if price else None,
                     "source": "confirmed" if c else ("reference" if r else "unknown (charged at the high default)")})
    return rows
