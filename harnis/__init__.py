# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Ahmad Karawash
"""Harnis: a multi-tenant agent harness."""
from importlib import metadata as _metadata

try:
    __version__ = _metadata.version("harnis")
except _metadata.PackageNotFoundError:  # running from a source tree without installing
    __version__ = "0.0.0+unknown"
