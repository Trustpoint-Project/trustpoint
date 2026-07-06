"""Shared helpers for the local tp_wizard PKCS#11 handoff."""

from __future__ import annotations

import os
from pathlib import Path

DEFAULT_LOCAL_DEV_MODULE_PATH = Path('/usr/lib/libsofthsm2.so')
DEFAULT_LOCAL_DEV_CONFIG_ENV_VAR = 'SOFTHSM2_CONF'
DEFAULT_LOCAL_DEV_SOFTHSM2_CONF = Path('/var/lib/trustpoint/hsm/config/softhsm2.conf')


def local_dev_pkcs11_module_path() -> Path:
    """Return the configured local-dev PKCS#11 module path."""
    configured_path = (os.getenv('TRUSTPOINT_LOCAL_HSM_MODULE_PATH') or '').strip()
    if configured_path:
        return Path(configured_path)
    return DEFAULT_LOCAL_DEV_MODULE_PATH


def local_dev_pkcs11_config_path() -> Path:
    """Return the configured local-dev PKCS#11 provider config path."""
    configured_path = (
        os.getenv('TRUSTPOINT_LOCAL_HSM_SOFTHSM2_CONF') or os.getenv(DEFAULT_LOCAL_DEV_CONFIG_ENV_VAR) or ''
    ).strip()
    if configured_path:
        return Path(configured_path)
    return DEFAULT_LOCAL_DEV_SOFTHSM2_CONF


def local_dev_pkcs11_config_env_var() -> str:
    """Return the env var used by the local-dev PKCS#11 module for its config."""
    return (os.getenv('TRUSTPOINT_LOCAL_HSM_CONFIG_ENV_VAR') or DEFAULT_LOCAL_DEV_CONFIG_ENV_VAR).strip()


def local_dev_pkcs11_handoff_available() -> bool:
    """Return whether tp_wizard exposed a local-dev PKCS#11 handoff."""
    return (
        os.getenv('TRUSTPOINT_LOCAL_HSM_ENABLED') == '1'
        and local_dev_pkcs11_module_path().is_file()
    )


def local_dev_pkcs11_config_available() -> bool:
    """Return whether tp_wizard exposed a readable local-dev PKCS#11 provider config."""
    return local_dev_pkcs11_handoff_available() and local_dev_pkcs11_config_path().is_file()
