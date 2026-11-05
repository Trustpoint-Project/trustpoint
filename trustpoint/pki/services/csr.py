# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Parsing and validation helpers for externally supplied certificate requests."""

from __future__ import annotations

import base64
import binascii
from enum import StrEnum
from typing import Literal

from cryptography import x509
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.serialization import Encoding
from django.utils.translation import gettext_lazy as _

from pki.util.cert_req_converter import JSONCertRequestConverter
from pki.util.keys import is_supported_public_key

MAX_CSR_SIZE = 1024 * 1024
# Bound Base64 wrapping and JSON/PEM transport overhead before decoding as well.
MAX_CSR_TRANSPORT_SIZE = 2 * MAX_CSR_SIZE


class CsrErrorCode(StrEnum):
    """Stable failures that protocol adapters can map to their own responses."""

    MISSING = 'missing'
    TOO_LARGE = 'too_large'
    MALFORMED = 'malformed'
    INVALID_SIGNATURE = 'invalid_signature'
    UNSUPPORTED_KEY = 'unsupported_key'
    UNSUPPORTED_SIGNATURE = 'unsupported_signature'
    MISSING_HASH = 'missing_hash'


class CsrValidationError(ValueError):
    """Raised when supplied CSR data cannot be used for certificate issuance."""

    def __init__(self, message: object, *, code: CsrErrorCode = CsrErrorCode.MALFORMED) -> None:
        """Retain a machine-readable reason alongside the existing user-facing error."""
        self.code = code
        super().__init__(message)


def validate_csr_size(size: int, *, transport: bool = False) -> None:
    """Bound encoded transport data and decoded PKCS#10 data before parsing."""
    if size > (MAX_CSR_TRANSPORT_SIZE if transport else MAX_CSR_SIZE):
        raise CsrValidationError(_('The supplied CSR is too large.'), code=CsrErrorCode.TOO_LARGE)


def decode_base64_csr(data: bytes) -> bytes:
    """Decode bounded Base64, allowing ASCII whitespace but rejecting other junk."""
    validate_csr_size(len(data), transport=True)
    try:
        decoded = base64.b64decode(b''.join(data.split()), validate=True)
    except (binascii.Error, ValueError, TypeError) as exc:
        raise CsrValidationError(_('The supplied CSR is not valid Base64.')) from exc
    validate_csr_size(len(decoded))
    return decoded


def load_csr(
    data: bytes, *, encoding: Literal['auto', 'pem', 'der'] = 'auto',
) -> x509.CertificateSigningRequest:
    """Parse exactly one bounded PEM or DER request without verifying its signature.

    Transport decoding belongs to protocol adapters. Splitting parsing from proof
    verification preserves HTTP component ordering; untrusted callers can use
    parse_csr to perform both steps together.
    """
    if not data:
        raise CsrValidationError(_('A CSR must be supplied.'), code=CsrErrorCode.MISSING)
    validate_csr_size(len(data))

    malformed_message = _('The supplied CSR is not a valid PKCS#10 certificate signing request.')
    if encoding == 'auto':
        encoding = 'pem' if data.lstrip().startswith(b'-----BEGIN') else 'der'
    if encoding == 'pem':
        pem = data.strip()
        label = b'NEW CERTIFICATE REQUEST' if pem.startswith(b'-----BEGIN NEW ') else b'CERTIFICATE REQUEST'
        if not (
            pem.startswith(b'-----BEGIN ' + label + b'-----')
            and pem.endswith(b'-----END ' + label + b'-----')
            and pem.count(b'-----BEGIN ') == 1
            and pem.count(b'-----END ') == 1
        ):
            raise CsrValidationError(malformed_message)
        try:
            return x509.load_pem_x509_csr(pem)
        except (ValueError, TypeError, UnsupportedAlgorithm) as exc:
            raise CsrValidationError(malformed_message) from exc
    if encoding != 'der':
        raise CsrValidationError(malformed_message)
    try:
        csr = x509.load_der_x509_csr(data)
    except (ValueError, TypeError, UnsupportedAlgorithm) as exc:
        raise CsrValidationError(malformed_message) from exc
    if csr.public_bytes(Encoding.DER) != data:
        raise CsrValidationError(malformed_message)
    return csr


def verify_csr_signature(csr: x509.CertificateSigningRequest) -> None:
    """Verify proof of possession using the CSR's encoded algorithm and parameters.

    cryptography handles RSA PKCS#1 v1.5, RSA-PSS parameters, ECDSA and hashless
    ML-DSA signatures. This check is separate from configurable security policy.
    """
    try:
        public_key = csr.public_key()
    except (ValueError, UnsupportedAlgorithm) as exc:
        raise CsrValidationError(
            _('The CSR public key algorithm is not supported.'), code=CsrErrorCode.UNSUPPORTED_KEY,
        ) from exc
    if not is_supported_public_key(public_key):
        raise CsrValidationError(
            _('The CSR public key algorithm is not supported.'), code=CsrErrorCode.UNSUPPORTED_KEY,
        )
    try:
        digest = csr.signature_hash_algorithm
    except (ValueError, UnsupportedAlgorithm) as exc:
        raise CsrValidationError(
            _('The CSR signature algorithm is not supported.'), code=CsrErrorCode.UNSUPPORTED_SIGNATURE,
        ) from exc
    if digest is None and isinstance(public_key, (rsa.RSAPublicKey, ec.EllipticCurvePublicKey)):
        raise CsrValidationError(
            _('CSR does not contain a signature hash algorithm.'), code=CsrErrorCode.MISSING_HASH,
        )
    try:
        valid = csr.is_signature_valid
    except UnsupportedAlgorithm as exc:
        raise CsrValidationError(
            _('The CSR signature algorithm is not supported.'), code=CsrErrorCode.UNSUPPORTED_SIGNATURE,
        ) from exc
    except (ValueError, InvalidSignature) as exc:
        raise CsrValidationError(_('The CSR signature is invalid.'), code=CsrErrorCode.INVALID_SIGNATURE) from exc
    if valid is not True:
        raise CsrValidationError(_('The CSR signature is invalid.'), code=CsrErrorCode.INVALID_SIGNATURE)


def parse_csr(
    data: bytes, *, encoding: Literal['auto', 'pem', 'der'] = 'auto',
) -> x509.CertificateSigningRequest:
    """Parse and cryptographically validate exactly one PEM or DER PKCS#10 CSR."""
    csr = load_csr(data, encoding=encoding)
    verify_csr_signature(csr)
    return csr


def csr_to_request(csr: x509.CertificateSigningRequest) -> dict[str, object]:
    """Convert a validated CSR into the existing certificate request format."""
    try:
        return JSONCertRequestConverter.to_json(csr, reject_unsupported_extensions=True)
    except ValueError as exc:
        error_message = str(exc)
        raise CsrValidationError(error_message) from exc
