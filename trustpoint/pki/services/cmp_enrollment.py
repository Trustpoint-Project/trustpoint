# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Shared client-side CMP enrollment.

Builds a profile-aware CSR, converts it to a CMP request, and sends it via CMP.

Reused by Issuing CA enrollment (``pki/services/ca_enrollment.py``) and, in the
future, other certificate types. The caller prepares a
``CmpCertificateRequestContext`` with the certificate profile, request data and
the signing (owner) credential, then delegates the CSR build, CMP message build
and CMP request to this helper.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from request.clients.cmp_client import CmpClient
from request.message_builder.cmp import CmpMessageBuilder
from request.operation_processor.csr_build import ProfileAwareCsrBuilder
from request.request_context import CmpCertificateRequestContext

if TYPE_CHECKING:
    from cryptography import x509

    from pki.models import CredentialModel
    from pki.models.truststore import TruststoreModel

__all__ = ['enroll_cmp']


def _recipient_name(truststore: TruststoreModel | None) -> str:
    """Extract the CMP recipient name from the trust store's first certificate."""
    if truststore is None:
        msg = 'No truststore configured for CMP - recipient name cannot be determined'
        raise ValueError(msg)
    first_cert_order = truststore.truststoreordermodel_set.order_by('order').first()
    if first_cert_order is None:
        msg = 'Truststore contains no certificates - cannot determine recipient name'
        raise ValueError(msg)
    ca_cert = first_cert_order.certificate.get_certificate_serializer().as_crypto()
    return ca_cert.subject.rfc4514_string()


def _signing_private_key(credential: CredentialModel | None) -> Any:
    """Return the signing credential's private key."""
    if credential is None:
        msg = 'No private key available for the credential'
        raise ValueError(msg)
    try:
        return credential.get_private_key()
    except (RuntimeError, TypeError, ValueError) as exc:
        msg = 'No usable private key is available for the credential.'
        raise ValueError(msg) from exc


def enroll_cmp(
    context: CmpCertificateRequestContext,
    *,
    sender_kid: int | None = None,
) -> tuple[x509.Certificate, list[x509.Certificate]]:
    """Build a profile-aware CSR, convert it to a CMP request, and enroll via CMP.

    Returns the issued leaf certificate and any additional certificates returned
    by the CMP server (as the ``(certificate, ca_certs)`` tuple from
    ``CmpClient.send_and_extract_certificate``).
    """
    csr_builder = ProfileAwareCsrBuilder()
    csr_builder.process_operation(context)
    csr = csr_builder.get_csr()
    context.cert_requested = csr

    if not csr.subject:
        msg = 'CSR does not have a subject - cannot build CMP request'
        raise ValueError(msg)

    cmp_context = CmpCertificateRequestContext(
        protocol='cmp',
        operation='certification',
        cmp_server_host=context.cmp_server_host,
        cmp_server_port=context.cmp_server_port,
        cmp_server_path=context.cmp_server_path,
        cmp_shared_secret=context.cmp_shared_secret,
        cmp_server_truststore=context.cmp_server_truststore,
        request_data={
            'subject': csr.subject,
            'public_key': csr.public_key(),
            'private_key': _signing_private_key(context.owner_credential),
            'recipient_name': _recipient_name(context.cmp_server_truststore),
            'extensions': list(csr.extensions) if csr.extensions else None,
            'use_initialization_request': False,
            'add_pop': True,
            'prepare_shared_secret_protection': True,
            'sender_kid': sender_kid,
        },
    )

    CmpMessageBuilder().build(cmp_context)
    pki_message = cmp_context.parsed_message

    return CmpClient(cmp_context).send_and_extract_certificate(pki_message, add_shared_secret_protection=True)
