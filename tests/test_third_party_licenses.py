# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Ahmad Karawash
"""scripts/third_party_licenses.py lists the runtime dependencies, with a
license for each, and leaves out Harnis itself and the dev tools."""
import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _load():
    spec = importlib.util.spec_from_file_location("tpl", ROOT / "scripts" / "third_party_licenses.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_lists_runtime_dependencies_with_licenses():
    tpl = _load()
    dists = tpl.collect()
    names = {d.metadata["Name"].lower() for d in dists}
    assert {"fastapi", "pgtern", "redis", "pyjwt"} <= names
    assert "harnis" not in names
    assert not names & {"pytest", "fakeredis", "mkdocs", "build", "psycopg"}  # dev, docs and optional extras stay out
    text = tpl.render(dists)
    assert text.startswith("# Third-party licenses")
    assert "| pgtern |" in text and "LGPL" not in text  # every required runtime dependency is permissive
    rows = [line for line in text.splitlines() if line.startswith("| ") and not line.startswith("| Package")]
    assert len(rows) == len(dists) and all(r.split("|")[3].strip() for r in rows)  # every row has a license
