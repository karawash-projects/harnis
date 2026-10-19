# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Ahmad Karawash
"""The README is also the PyPI project page, where relative links and in-page
anchors do not resolve. Every link in it must be absolute."""
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BASE = "https://github.com/karawash-projects/harnis"


def test_readme_links_are_absolute_and_point_at_existing_files():
    text = (ROOT / "README.md").read_text(encoding="utf-8")
    links = re.findall(r"\]\(([^)\s]+)\)", text) + re.findall(r'(?:href|src)="([^"]+)"', text)
    relative = [u for u in links if not re.match(r"(https?|mailto):", u)]
    assert not relative, f"relative links break on PyPI: {relative}"
    for u in links:
        m = re.match(re.escape(BASE) + r"/(?:blob|tree)/main/([^#]+)", u)
        if m:
            assert (ROOT / m.group(1)).exists(), f"README links to a missing file: {u}"
