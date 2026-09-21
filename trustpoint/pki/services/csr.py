# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Parsing and validation helpers for externally supplied certificate requests."""

from __future__ import annotations

from cryptography import x509
from django.utils.translation import gettext_lazy as _

from pki.util.cert_req_converter import JSONCertRequestConverter
from pki.util.keys import is_supported_public_key

MAX_CSR_SIZE = 1024 * 1024


class CsrValidationError(ValueError):
    """Raised when supplied CSR data cannot be used for certificate issuance."""


def parse_csr(data: bytes) -> x509.CertificateSigningRequest:
    """Parse and cryptographically validate a PEM or DER encoded PKCS#10 CSR."""
    if not data:
        raise CsrValidationError(_('A CSR must be supplied.'))
    if len(data) > MAX_CSR_SIZE:
        raise CsrValidationError(_('The supplied CSR is too large.'))

    try:
        csr = (
            x509.load_pem_x509_csr(data)
            if b'-----BEGIN' in data[:128]
            else x509.load_der_x509_csr(data)
        )
    except ValueError as exc:
        raise CsrValidationError(
            _('The supplied CSR is not a valid PKCS#10 certificate signing request.')
        ) from exc

    if not csr.is_signature_valid:
        raise CsrValidationError(_('The CSR signature is invalid.'))
    if not is_supported_public_key(csr.public_key()):
        raise CsrValidationError(_('The CSR public key algorithm is not supported.'))
    return csr


def csr_to_request(csr: x509.CertificateSigningRequest) -> dict[str, object]:
    """Convert a validated CSR into the existing certificate request format."""
    try:
        return JSONCertRequestConverter.to_json(csr, reject_unsupported_extensions=True)
    except ValueError as exc:
        error_message = str(exc)
        raise CsrValidationError(error_message) from exc
