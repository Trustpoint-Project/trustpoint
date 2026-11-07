# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Verify signed audit snapshots without Django or a Trustpoint database.

Run: python -I trustpoint/util/audit_log_export.py export.json --trusted-certificate trusted.pem
"""

from __future__ import annotations

import argparse
import base64
import json
import re
from pathlib import Path
from typing import Any, NoReturn

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

AUDIT_EXPORT_CONTEXT = 'trustpoint:audit-log:v1'


def encode_json(value: dict[str, Any]) -> bytes:
    """Serialize JSON as UTF-8; JWS signs these exact bytes without canonicalization."""
    return json.dumps(value, separators=(',', ':'), ensure_ascii=False, allow_nan=False).encode('utf-8')


def base64url_encode(value: bytes) -> str:
    """Encode a JWS component using unpadded base64url (RFC 7515 section 2)."""
    return base64.urlsafe_b64encode(value).rstrip(b'=').decode('ascii')


def base64url_decode(value: str) -> bytes:
    """Reject padding, invalid alphabet characters, and noncanonical pad bits."""
    if not isinstance(value, str) or re.fullmatch(r'[A-Za-z0-9_-]*', value) is None:
        msg = 'Invalid JWS base64url encoding.'
        raise ValueError(msg)
    decoded = base64.b64decode(value + '=' * (-len(value) % 4), altchars=b'-_', validate=True)
    if base64url_encode(decoded) != value:
        msg = 'Invalid JWS base64url encoding.'
        raise ValueError(msg)
    return decoded


def _unique_object(items: list[tuple[str, Any]]) -> dict[str, Any]:
    """Reject ambiguous JSON objects at the verification boundary."""
    result: dict[str, Any] = {}
    for key, value in items:
        if key in result:
            msg = 'Duplicate JSON member.'
            raise ValueError(msg)
        result[key] = value
    return result


def _reject_constant(value: str) -> NoReturn:
    """Reject non-JSON numeric constants accepted by Python's default parser."""
    msg = f'Invalid JSON constant: {value}'
    raise ValueError(msg)


def load_json(value: bytes | str) -> dict[str, Any]:
    """Parse an unambiguous JSON object from a JWS component or document."""
    if isinstance(value, bytes):
        value = value.decode('utf-8')
    result = json.loads(value, object_pairs_hook=_unique_object, parse_constant=_reject_constant)
    if not isinstance(result, dict):
        msg = 'Expected a JSON object.'
        raise TypeError(msg)
    return result


def certificate_signature_algorithm(certificate: x509.Certificate) -> tuple[hashes.HashAlgorithm, str]:
    """Return the fixed signature algorithm for supported traceability keys."""
    key = certificate.public_key()
    if isinstance(key, ec.EllipticCurvePublicKey):
        if isinstance(key.curve, ec.SECP256R1):
            return hashes.SHA256(), 'ES256'
        if isinstance(key.curve, ec.SECP384R1):
            return hashes.SHA384(), 'ES384'
    msg = 'Unsupported audit export signing key.'
    raise ValueError(msg)


def verify_export(document: dict[str, Any], trusted_certificate_pem: bytes) -> dict[str, Any]:
    """Verify our flattened JWS profile against a pinned historical signing certificate."""
    try:
        if set(document) != {'protected', 'payload', 'signature'}:
            raise ValueError  # noqa: TRY301
        header = load_json(base64url_decode(document['protected']))
        if set(header) != {'alg', 'cty', 'x5c'} or header['cty'] != 'application/json':
            raise ValueError  # noqa: TRY301
        if not isinstance(header['x5c'], list) or len(header['x5c']) != 1:
            raise ValueError  # noqa: TRY301
        certificate = x509.load_der_x509_certificate(base64.b64decode(header['x5c'][0], validate=True))
        trusted = x509.load_pem_x509_certificate(trusted_certificate_pem)
        fingerprint = certificate.fingerprint(hashes.SHA256())
        if fingerprint != trusted.fingerprint(hashes.SHA256()):
            raise ValueError  # noqa: TRY301
        # Traceability certificates are self-signed and trusted by exact certificate pinning.
        certificate.verify_directly_issued_by(trusted)
        digest, algorithm = certificate_signature_algorithm(certificate)
        if header['alg'] != algorithm:
            raise ValueError  # noqa: TRY301
        key = certificate.public_key()
        if not isinstance(key, ec.EllipticCurvePublicKey):
            raise TypeError  # noqa: TRY301
        signature = base64url_decode(document['signature'])
        coordinate_size = digest.digest_size
        if len(signature) != 2 * coordinate_size:
            raise ValueError  # noqa: TRY301
        der_signature = encode_dss_signature(
            int.from_bytes(signature[:coordinate_size], 'big'),
            int.from_bytes(signature[coordinate_size:], 'big'),
        )
        payload_bytes = base64url_decode(document['payload'])
        signing_input = f'{document["protected"]}.{document["payload"]}'.encode('ascii')
        key.verify(der_signature, signing_input, ec.ECDSA(digest))
        payload = load_json(payload_bytes)
        if (
            payload['context'] != AUDIT_EXPORT_CONTEXT
            or not isinstance(payload['entries'], list)
            or type(payload['entry_count']) is not int
            or payload['entry_count'] != len(payload['entries'])
            or payload['signer']['algorithm'] != algorithm
            or payload['signer']['certificate_fingerprint_sha256'] != fingerprint.hex()
        ):
            raise ValueError  # noqa: TRY301
    except (InvalidSignature, KeyError, TypeError, ValueError, AttributeError) as error:
        msg = 'Invalid audit export or untrusted signing certificate.'
        raise ValueError(msg) from error
    return dict(payload)


def main() -> None:
    """Verify a downloaded snapshot using an independently obtained certificate."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('export', type=Path)
    parser.add_argument('--trusted-certificate', type=Path, required=True)
    args = parser.parse_args()
    try:
        payload = verify_export(load_json(args.export.read_bytes()), args.trusted_certificate.read_bytes())
    except (OSError, TypeError, ValueError) as error:
        parser.exit(1, f'Verification failed: {error}\n')
    print(f'Verified {payload["entry_count"]} entries; context: {payload["context"]}')  # noqa: T201


if __name__ == '__main__':
    main()
