"""Shared helpers for the local tp_wizard PKCS#11 handoff."""

from __future__ import annotations

import os
from pathlib import Path

DEFAULT_LOCAL_DEV_MODULE_PATH = Path('/usr/lib/libsofthsm2.so')


def local_dev_pkcs11_module_path() -> Path:
    """Return the configured local-dev PKCS#11 module path."""
    configured_path = (os.getenv('TRUSTPOINT_LOCAL_HSM_MODULE_PATH') or '').strip()
    if configured_path:
        return Path(configured_path)
    return DEFAULT_LOCAL_DEV_MODULE_PATH


def local_dev_pkcs11_handoff_available() -> bool:
    """Return whether tp_wizard exposed a local-dev PKCS#11 handoff."""
    return (
        os.getenv('TRUSTPOINT_LOCAL_HSM_ENABLED') == '1'
        and local_dev_pkcs11_module_path().is_file()
    )
