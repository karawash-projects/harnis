#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Ahmad Karawash
"""Assemble and build the documentation site.

The pages are docs/*.md plus the README as the home page. The README is also
the PyPI description, so its links are absolute GitHub URLs; on the site,
links to docs pages and images become relative, so readers stay on the site.

    python scripts/build_docs.py            # build into site/ (fails on broken links)
    python scripts/build_docs.py --serve    # live preview on http://127.0.0.1:8001
"""
from __future__ import annotations

import argparse
import re
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BUILD = ROOT / ".docs-build"
REPO = "https://github.com/karawash-projects/harnis"
RAW = "https://raw.githubusercontent.com/karawash-projects/harnis/main"


def home_page(readme: str) -> str:
    # Links to pages under docs/ -> relative page links.
    text = re.sub(re.escape(REPO) + r"/blob/main/docs/([\w\-./]+\.md)", r"\1", readme)
    # Images under docs/ -> relative image paths.
    text = re.sub(re.escape(RAW) + r"/docs/([\w\-./]+)", r"\1", text)
    # Links to the README's own sections -> in-page anchors.
    text = re.sub(re.escape(REPO) + r"#([\w\-]+)\)", r"#\1)", text)
    return text


def assemble() -> None:
    if BUILD.exists():
        shutil.rmtree(BUILD)
    shutil.copytree(ROOT / "docs", BUILD)
    shutil.copy(ROOT / "harnis" / "static" / "favicon.svg", BUILD / "images" / "logo.svg")
    (BUILD / "index.md").write_text(home_page((ROOT / "README.md").read_text(encoding="utf-8")),
                                    encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--serve", action="store_true", help="live preview instead of a build")
    a = ap.parse_args(argv)
    assemble()
    cmd = [sys.executable, "-m", "mkdocs"]
    cmd += ["serve", "-a", "127.0.0.1:8001"] if a.serve else ["build", "--strict", "--site-dir", "site"]
    return subprocess.run(cmd, cwd=ROOT).returncode


if __name__ == "__main__":
    sys.exit(main())
