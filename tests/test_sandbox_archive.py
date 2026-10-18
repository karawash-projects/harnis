# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Ahmad Karawash
"""Archive handling for copy-mode sandboxes. No Docker needed."""
import io
import tarfile

import pytest

from harnis.sandbox import SANDBOX_UID, WorkspaceTooLarge, pack_workspace, unpack_workspace


def make_tar(entries):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        for name, kind, payload in entries:
            info = tarfile.TarInfo(name)
            if kind == "dir":
                info.type = tarfile.DIRTYPE
                tar.addfile(info)
            elif kind == "sym":
                info.type, info.linkname = tarfile.SYMTYPE, payload
                tar.addfile(info)
            elif kind == "hard":
                info.type, info.linkname = tarfile.LNKTYPE, payload
                tar.addfile(info)
            else:
                data = payload.encode()
                info.size = len(data)
                tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def test_pack_owns_files_as_sandbox_user_and_uses_posix_names(tmp_path):
    (tmp_path / "a").mkdir()
    (tmp_path / "a" / "b.py").write_text("x", encoding="utf-8")
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "config").write_text("secret", encoding="utf-8")
    with tarfile.open(fileobj=io.BytesIO(pack_workspace(tmp_path, 10_000))) as tar:
        members = {m.name: m for m in tar}
    assert "workspace/a/b.py" in members and "workspace/.git/config" not in members
    assert all(m.uid == SANDBOX_UID for m in members.values())


def test_pack_enforces_size_limit(tmp_path):
    (tmp_path / "big").write_bytes(b"x" * 2000)
    with pytest.raises(WorkspaceTooLarge):
        pack_workspace(tmp_path, 1000)


def test_unpack_rejects_hostile_members(tmp_path):
    ws = tmp_path / "ws"
    ws.mkdir()
    outside = tmp_path / "outside.txt"
    data = make_tar([
        ("workspace", "dir", ""),
        ("workspace/ok.txt", "file", "fine"),
        ("workspace/../outside.txt", "file", "pwned"),
        ("/etc/evil", "file", "pwned"),
        ("other/file", "file", "pwned"),
        ("workspace/link", "sym", "/etc/passwd"),
        ("workspace/hard", "hard", "/etc/passwd"),
    ])
    unpack_workspace(data, ws, 10_000, 100)
    assert (ws / "ok.txt").read_text(encoding="utf-8") == "fine"
    assert not outside.exists()
    assert sorted(p.name for p in ws.iterdir()) == ["ok.txt"]


def test_unpack_deletes_removed_files_and_preserves_bytes(tmp_path):
    (tmp_path / "old.txt").write_text("old", encoding="utf-8")
    data = make_tar([("workspace", "dir", ""), ("workspace/crlf.txt", "file", "a\r\nb\n")])
    unpack_workspace(data, tmp_path, 10_000, 100)
    assert not (tmp_path / "old.txt").exists()
    assert (tmp_path / "crlf.txt").read_bytes() == b"a\r\nb\n"


def test_unpack_enforces_limits(tmp_path):
    data = make_tar([("workspace", "dir", "")] + [(f"workspace/f{i}", "file", "x") for i in range(5)])
    with pytest.raises(WorkspaceTooLarge):
        unpack_workspace(data, tmp_path, 10_000, 3)
