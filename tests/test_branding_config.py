# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Ahmad Karawash
"""Console branding settings are validated at startup."""
import pytest

from harnis.api import _load_logo
from harnis.config import Settings


def s(**kw):
    return Settings(_env_file=None, **kw)


def test_defaults_keep_harnis():
    c = s()
    assert c.console_brand_name == "Harnis" and not c.console_accent and not c.console_help_url


@pytest.mark.parametrize("bad", ["red", "#fff", "#12345g", "1f5c4f", "url(x)"])
def test_accent_must_be_a_hex_colour(bad):
    with pytest.raises(ValueError, match="CONSOLE_ACCENT"):
        s(console_accent=bad)


@pytest.mark.parametrize("bad", ["javascript:alert(1)", "ftp://x", "//evil.example"])
def test_help_url_scheme_is_checked(bad):
    with pytest.raises(ValueError, match="CONSOLE_HELP_URL"):
        s(console_help_url=bad)


def test_blank_brand_name_falls_back():
    assert s(console_brand_name="  ").console_brand_name == "Harnis"


def test_logo_must_be_a_small_image_file(tmp_path):
    assert _load_logo("") is None
    ok = tmp_path / "a.png"
    ok.write_bytes(b"\x89PNG")
    assert _load_logo(str(ok)) == (b"\x89PNG", "image/png")
    with pytest.raises(RuntimeError, match="png"):
        _load_logo(str(tmp_path / "a.txt"))
    with pytest.raises(RuntimeError, match="could not be read"):
        _load_logo(str(tmp_path / "missing.png"))
    big = tmp_path / "big.png"
    big.write_bytes(b"x" * (300 * 1024))
    with pytest.raises(RuntimeError, match="larger"):
        _load_logo(str(big))
