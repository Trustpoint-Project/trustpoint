"""Helpers for one-time PKCS#11 wizard staging files."""

from __future__ import annotations

import tempfile
from pathlib import Path

WIZARD_PKCS11_STAGING_ROOT = Path(tempfile.gettempdir()) / 'trustpoint-wizard' / 'pkcs11'


def wizard_pkcs11_staging_root() -> Path:
    """Return the private temporary directory used for wizard PKCS#11 staging."""
    return WIZARD_PKCS11_STAGING_ROOT


def resolve_wizard_pkcs11_staged_path(value: str | Path | None) -> Path | None:
    """Return a resolved staged path only when it stays inside the wizard staging root."""
    if not value:
        return None

    try:
        candidate = Path(value).resolve(strict=False)
    except (OSError, TypeError, ValueError):
        return None

    root = WIZARD_PKCS11_STAGING_ROOT.resolve(strict=False)
    if not candidate.is_relative_to(root):
        return None
    return candidate


def existing_wizard_pkcs11_staged_file(value: str | Path | None) -> Path | None:
    """Return a staged file path when it still exists and is a regular file."""
    candidate = resolve_wizard_pkcs11_staged_path(value)
    if candidate is None or not candidate.is_file():
        return None
    return candidate


def cleanup_wizard_pkcs11_staged_path(value: str | Path | None) -> None:
    """Delete a staged file and prune empty parent directories inside the staging root."""
    candidate = resolve_wizard_pkcs11_staged_path(value)
    if candidate is None:
        return

    try:
        if candidate.is_file():
            candidate.unlink()
    except OSError:
        return

    root = WIZARD_PKCS11_STAGING_ROOT.resolve(strict=False)
    for parent in candidate.parents:
        if parent == root:
            break
        try:
            parent.rmdir()
        except OSError:
            break

    try:
        root.rmdir()
    except OSError:
        return
