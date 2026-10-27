# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Activate a staged TLS credential in the operational database and Nginx."""

from __future__ import annotations

from typing import TYPE_CHECKING

from cryptography.hazmat.primitives import hashes

from pki.models import CredentialModel
from pki.models.truststore import ActiveTrustpointTlsServerCredentialModel
from setup_wizard.tls_credential import clear_staged_tls_credential

if TYPE_CHECKING:
    import logging
    from collections.abc import Callable

    from trustpoint_core.serializer import CredentialSerializer


def activate_staged_tls_credential(
    credential_serializer: CredentialSerializer,
    *,
    write_pem_files: Callable[[CredentialModel], None],
    apply_to_nginx: Callable[[], None],
    logger: logging.Logger,
) -> None:
    """Persist and apply the credential, then clear staging after successful activation."""
    staged_tls_credential = CredentialModel.save_credential_serializer(
        credential_serializer=credential_serializer,
        credential_type=CredentialModel.CredentialTypeChoice.TRUSTPOINT_TLS_SERVER,
    )
    active_tls, _ = ActiveTrustpointTlsServerCredentialModel.objects.get_or_create(id=1)
    active_tls.credential = staged_tls_credential
    active_tls.save()

    write_pem_files(staged_tls_credential)
    apply_to_nginx()
    sha256_fingerprint = staged_tls_credential.get_certificate().fingerprint(hashes.SHA256())
    formatted_fingerprint = ':'.join(f'{byte:02X}' for byte in sha256_fingerprint)
    logger.info('TLS SHA256 fingerprint: %s', formatted_fingerprint)
    clear_staged_tls_credential()
