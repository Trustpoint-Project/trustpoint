# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Shared client-side EST enrollment: build a profile-aware CSR and send it via EST.

Reused by Issuing CA enrollment (``pki/services/ca_enrollment.py``), DevOwnerID
enrollment (``pki/services/owner_credential.py``) and TLS server credential
enrollment (``pki/services/tls_server_issuance.py``). The caller prepares an
``EstCertificateRequestContext`` with the certificate profile, request data and
the signing (owner) credential, then delegates the CSR build, re-sign and EST
request to this helper.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from request.clients import EstClient
from request.operation_processor.csr_build import ProfileAwareCsrBuilder
from request.operation_processor.csr_sign import EstDeviceCsrSignProcessor

if TYPE_CHECKING:
    from cryptography import x509

    from request.request_context import EstCertificateRequestContext

__all__ = ['enroll_est']


def enroll_est(context: EstCertificateRequestContext) -> tuple[x509.Certificate, list[x509.Certificate]]:
    """Build a profile-aware CSR from ``context`` and enroll it via EST.

    Returns the issued leaf certificate and any additional certificates returned
    by the EST server (as the ``(certificate, ca_certs)`` tuple from
    ``EstClient.simple_enroll``).
    """
    csr_builder = ProfileAwareCsrBuilder()
    csr_builder.process_operation(context)
    context.cert_requested = csr_builder.get_csr()

    csr_signer = EstDeviceCsrSignProcessor()
    csr_signer.process_operation(context)
    signed_csr = csr_signer.get_signed_csr()

    return EstClient(context).simple_enroll(signed_csr)
