# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Ahmad Karawash
"""Path policy: which files agents may read and write."""
import pytest

from harnis.pathpolicy import PathPolicy
from harnis.tools import ToolContext, _list, _read, _write, ReadFile, WriteFile


def test_patterns_match_folders_case_insensitively_and_deny_beats_allow():
    p = PathPolicy.from_dict({"deny_write": [".github/**", "**/*.pem", "docs/"], "deny_read": ["**/.env"],
                              "allow_write": ["src/**", "tests/**", "docs/**"]})
    assert p.write_denied(".github/workflows/ci.yml")
    assert p.write_denied("src/keys/server.PEM")                 # case-insensitive, any depth
    assert p.write_denied("docs/intro.md")                        # deny wins over allow ("docs/" means everything under it)
    assert p.write_denied("README.md") and "limited to" in p.write_denied("README.md")
    assert p.write_denied("src/app/main.py") is None and p.write_denied("tests/test_x.py") is None
    assert p.read_denied(".env") and p.read_denied("a/b/.ENV") and p.read_denied("src/main.py") is None
    assert p.write_denied("src/.github/x") is None                # "**" prefix rules only match where written


def test_policy_file_is_validated(tmp_path):
    f = tmp_path / "p.toml"
    f.write_text('deny_write = ["a/**"]\nallow_write = ["src/**"]\n')
    assert PathPolicy.load(f).write_denied("a/x")
    for bad in ('deny_write = "x"', 'deny_wrte = ["x"]', 'deny_write = ["/etc/passwd"]', 'deny_write = ["../x"]',
                'deny_write = [""]', "not toml ["):
        f.write_text(bad)
        with pytest.raises(ValueError):
            PathPolicy.load(f)
    with pytest.raises(ValueError):
        PathPolicy.load(tmp_path / "missing.toml")


def test_file_tools_enforce_the_policy_and_hide_unreadable_files(tmp_path, sandbox):
    (tmp_path / "secrets").mkdir()
    (tmp_path / "secrets" / "key.txt").write_text("hush")
    (tmp_path / "main.py").write_text("print(1)")
    ctx = ToolContext(tmp_path, sandbox, paths=PathPolicy.from_dict({"deny_read": ["secrets/**"], "deny_write": ["locked.py"]}))
    out, err = _read(ctx, ReadFile(path="secrets/key.txt"))
    assert err and "not allowed" in out and "hush" not in out
    assert _read(ctx, ReadFile(path="main.py")) == ("print(1)", False)
    listing, _ = _list(ctx, None)
    assert "main.py" in listing and "secrets" not in listing
    out, err = _write(ctx, WriteFile(path="locked.py", content="x"))
    assert err and not (tmp_path / "locked.py").exists()
    assert _write(ctx, WriteFile(path="free.py", content="x"))[1] is False
    out, err = _read(ctx, ReadFile(path="../x"))                  # the existing path rules still apply
    assert err and "escapes" in out


def test_a_write_the_policy_forbids_is_refused_without_asking_a_reviewer(store, make_orch):
    orch = make_orch(store, paths=PathPolicy.from_dict({"deny_write": ["calc.py", "test_calc.py"]}))
    rec = orch.start_turn(store.new_session(), "create calc.py")
    assert rec.status != "awaiting_approval"                      # nobody was asked to approve it
    assert not store.approvals
    assert any("path_denied" in a for a in store.audits)


def test_the_same_request_without_a_policy_still_needs_approval(store, make_orch):
    rec = make_orch(store).start_turn(store.new_session(), "create calc.py")
    assert rec.status == "awaiting_approval"


def test_a_policy_that_leaves_other_files_open_still_asks_for_approval(store, make_orch):
    """Only the denied file is refused: the agent's next, allowed write goes to a reviewer as usual."""
    rec = make_orch(store, paths=PathPolicy.from_dict({"deny_write": ["calc.py"]})).start_turn(store.new_session(), "create calc.py")
    assert rec.status == "awaiting_approval"
    assert [a["action"]["args"]["path"] for a in store.approvals.values()] == ["test_calc.py"]
    assert any("path_denied" in a for a in store.audits)


@pytest.mark.integration  # builds the whole app, so needs Postgres and Redis
def test_a_broken_policy_file_stops_startup_instead_of_being_ignored(tmp_path, monkeypatch):
    from harnis.api import create_app
    from harnis.config import Settings

    bad = tmp_path / "bad.toml"
    bad.write_text('deny_wrte = ["x"]')
    with pytest.raises(ValueError, match="unknown path policy key"):
        create_app(Settings(_env_file=None, workspaces_dir=str(tmp_path / "ws"), path_policy_file=str(bad)))
