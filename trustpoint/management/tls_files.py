# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Write exported TLS credentials to the configured server paths."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path

    from pki.models.credential import CredentialModel


def write_tls_pem_files(credential: CredentialModel, *, key_path: Path, cert_path: Path, chain_path: Path) -> None:
    """Write a credential's PEM files and remove a stale chain when it is empty."""
    private_key_pem = credential.get_private_key_serializer().as_pkcs8_pem().decode()
    certificate_pem = credential.get_certificate_serializer().as_pem().decode()
    chain_pem = credential.get_certificate_chain_serializer().as_pem().decode()

    key_path.write_text(private_key_pem)
    cert_path.write_text(certificate_pem)
    if chain_pem.strip():
        chain_path.write_text(chain_pem)
    elif chain_path.exists():
        chain_path.unlink()
