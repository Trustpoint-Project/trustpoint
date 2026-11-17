# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Verify checkpoint-anchored audit evidence packages without Django.

Run: python -I trustpoint/util/audit_log_export.py evidence.json \
    --trusted-certificate signing-generation.pem
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any, NoReturn

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

EVIDENCE_FORMAT = 'trustpoint:audit-evidence:v1'
CHECKPOINT_CONTEXT = 'trustpoint:audit-checkpoint:v1'
GENESIS_HASH = '0' * 64
WARNING_CODES = frozenset(
    {
        'CHECKPOINT_COVERAGE_NOT_EXPORTED',
    }
)


def encode_json(value: dict[str, Any]) -> bytes:
    """Serialize JSON as UTF-8; JWS signs these exact bytes without canonicalization."""
    return json.dumps(value, separators=(',', ':'), ensure_ascii=False, allow_nan=False).encode('utf-8')


def canonical_json(value: dict[str, Any]) -> bytes:
    """Serialize a mapping deterministically for hash chains and checkpoint signing."""
    return json.dumps(
        value,
        sort_keys=True,
        separators=(',', ':'),
        ensure_ascii=False,
        allow_nan=False,
    ).encode('utf-8')


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
    """Return the fixed signature algorithm for supported signing keys."""
    key = certificate.public_key()
    if isinstance(key, ec.EllipticCurvePublicKey):
        if isinstance(key.curve, ec.SECP256R1):
            return hashes.SHA256(), 'ES256'
        if isinstance(key.curve, ec.SECP384R1):
            return hashes.SHA384(), 'ES384'
    msg = 'Unsupported audit export signing key.'
    raise ValueError(msg)


def _finding(code: str, sequence: int | None, detail: str) -> dict[str, Any]:
    return {'code': code, 'sequence': sequence, 'detail': detail}


def _invalid(message: str, error_type: type[Exception] = ValueError) -> NoReturn:
    raise error_type(message)


def _entry_payload(row: dict[str, Any]) -> dict[str, Any]:
    return {
        'v': 1,
        'sequence': row['sequence'],
        'previous_hash': row['previous_hash'],
        'timestamp': row['timestamp'],
        'operation_type': row['operation_type'],
        'target_type': row['target_type'],
        'target_object_id': row['target_object_id'],
        'target_display': row['target_display'],
        'actor_label': row['actor_label'],
        'details': row['details'] or {},
    }


def _entry_hash(row: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_json(_entry_payload(row))).hexdigest()


def _load_certificate(pem: str) -> x509.Certificate:
    return x509.load_pem_x509_certificate(pem.encode('ascii'))


def _trusted_fingerprints(trusted_certificates_pem: list[bytes]) -> set[bytes]:
    fingerprints: set[bytes] = set()
    for pem in trusted_certificates_pem:
        certificate = x509.load_pem_x509_certificate(pem)
        fingerprints.add(certificate.fingerprint(hashes.SHA256()))
    return fingerprints


def _verify_signature(  # noqa: PLR0913 - explicit cryptographic parameters
    *,
    certificate: x509.Certificate,
    signature: bytes,
    data: bytes,
    trusted_fingerprints: set[bytes],
    findings: list[dict[str, Any]],
    sequence: int | None,
) -> None:
    """Verify a DER ECDSA signature and its certificate against the pinned trust set."""
    digest, _algorithm = certificate_signature_algorithm(certificate)
    if certificate.fingerprint(hashes.SHA256()) not in trusted_fingerprints:
        findings.append(
            _finding(
                'UNTRUSTED_CERTIFICATE',
                sequence,
                'The signing certificate fingerprint is not in the supplied trust set.',
            )
        )
    try:
        public_key = certificate.public_key()
        if not isinstance(public_key, ec.EllipticCurvePublicKey):
            _invalid('not EC', TypeError)
        public_key.verify(signature, data, ec.ECDSA(digest))
    except (InvalidSignature, TypeError, ValueError):
        findings.append(_finding('INVALID_SIGNATURE', sequence, 'The signature does not verify.'))


def _checkpoint_payload(  # noqa: PLR0911 - validation exits on the first malformed field
    checkpoint: dict[str, Any],
) -> dict[str, Any] | None:
    """Validate the self-contained signed checkpoint object and return its payload."""
    if not isinstance(checkpoint, dict) or set(checkpoint) != {'payload', 'signature'}:
        return None
    payload = checkpoint.get('payload')
    if not isinstance(payload, dict):
        return None
    if payload.get('v') != 1 or payload.get('context') != CHECKPOINT_CONTEXT:
        return None
    integers = ('checkpoint_number', 'first_sequence', 'last_sequence', 'entry_count')
    strings = ('head_hash', 'previous_checkpoint_hash', 'signed_at')
    if any(not isinstance(payload.get(key), int) for key in integers):
        return None
    if any(not isinstance(payload.get(key), str) for key in strings):
        return None
    signer = payload.get('signer')
    if not isinstance(signer, dict):
        return None
    signer_integers = ('credential_id', 'generation_id', 'generation_number')
    signer_strings = ('credential_name', 'certificate_fingerprint_sha256')
    if any(not isinstance(signer.get(key), int) for key in signer_integers):
        return None
    if any(not isinstance(signer.get(key), str) for key in signer_strings):
        return None
    return payload


def _verify_checkpoint(  # noqa: C901, PLR0913 - checkpoint context is intentionally explicit
    checkpoint: dict[str, Any],
    payload: dict[str, Any],
    entry_hashes: dict[int, str],
    previous_checkpoint_last: int,
    *,
    complete_chain: bool,
    certificates: dict[str, x509.Certificate],
    trusted_fingerprints: set[bytes],
    findings: list[dict[str, Any]],
) -> bool:
    """Verify one checkpoint's signature and optional chain coverage."""
    coverage_verified = True
    try:
        signature = base64.b64decode(str(checkpoint['signature']), validate=True)
        fingerprint = payload['signer']['certificate_fingerprint_sha256'].upper()
        certificate = certificates.get(fingerprint)
        if certificate is None:
            findings.append(
                _finding(
                    'MISSING_CERTIFICATE',
                    payload['last_sequence'],
                    'The signing certificate referenced by the checkpoint is missing.',
                )
            )
            return False
        if certificate.fingerprint(hashes.SHA256()).hex().upper() != fingerprint:
            findings.append(
                _finding(
                    'CERTIFICATE_MISMATCH',
                    payload['last_sequence'],
                    'The certificate fingerprint does not match the signed payload.',
                )
            )
        _verify_signature(
            certificate=certificate,
            signature=signature,
            data=canonical_json(payload),
            trusted_fingerprints=trusted_fingerprints,
            findings=findings,
            sequence=payload['last_sequence'],
        )
    except (KeyError, TypeError, ValueError):
        findings.append(_finding('INVALID_CHECKPOINT', None, 'The checkpoint metadata or signature is malformed.'))
        return False

    last_sequence = payload['last_sequence']
    if last_sequence == 0:
        if (
            payload['checkpoint_number'] != 1
            or payload['first_sequence'] != 1
            or payload['entry_count'] != 0
            or payload['head_hash'] != GENESIS_HASH
        ):
            findings.append(
                _finding('CHECKPOINT_PAYLOAD_MISMATCH', 0, 'The genesis checkpoint has inconsistent coverage.')
            )
    else:
        expected_first = previous_checkpoint_last + 1
        if payload['first_sequence'] != expected_first and complete_chain:
            findings.append(
                _finding(
                    'CHECKPOINT_GAP',
                    last_sequence,
                    f'Expected first sequence {expected_first}, found {payload["first_sequence"]}.',
                )
            )
        expected_count = last_sequence - payload['first_sequence'] + 1
        if payload['entry_count'] != expected_count:
            findings.append(
                _finding(
                    'CHECKPOINT_PAYLOAD_MISMATCH',
                    last_sequence,
                    'The checkpoint entry count does not match its range.',
                )
            )
        exported_head = entry_hashes.get(last_sequence)
        if exported_head is None:
            coverage_verified = False
            if complete_chain:
                findings.append(
                    _finding(
                        'CHAIN_TRUNCATED',
                        last_sequence,
                        'The event covered by this checkpoint is missing from the exported chain.',
                    )
                )
        elif exported_head != payload['head_hash']:
            findings.append(
                _finding(
                    'CHECKPOINT_HEAD_MISMATCH',
                    last_sequence,
                    'The checkpoint head hash does not match the exported event at that sequence.',
                )
            )
    return coverage_verified


def _verify_snapshot(  # noqa: C901 - JWS profile checks are deliberately sequential
    document: dict[str, Any],
    evidence: dict[str, Any],
    trusted_fingerprints: set[bytes],
    findings: list[dict[str, Any]],
) -> None:
    signature = document.get('snapshot_signature')
    if signature is None:
        if evidence.get('scope') == 'filtered':
            findings.append(
                _finding('MISSING_SNAPSHOT_SIGNATURE', None, 'Filtered evidence requires a snapshot signature.')
            )
        return
    try:
        if not isinstance(signature, dict) or set(signature) != {'protected', 'payload', 'signature'}:
            _invalid('invalid JWS')
        header = load_json(base64url_decode(str(signature['protected'])))
        if set(header) != {'alg', 'cty', 'x5c'} or header['cty'] != 'application/json':
            _invalid('invalid JWS header')
        if not isinstance(header['x5c'], list) or len(header['x5c']) != 1:
            _invalid('invalid JWS certificate')
        certificate = x509.load_der_x509_certificate(base64.b64decode(header['x5c'][0], validate=True))
        digest, algorithm = certificate_signature_algorithm(certificate)
        if header['alg'] != algorithm:
            _invalid('invalid JWS algorithm')
        fingerprint = certificate.fingerprint(hashes.SHA256())
        if fingerprint not in trusted_fingerprints:
            findings.append(
                _finding(
                    'UNTRUSTED_CERTIFICATE',
                    None,
                    'The snapshot signing certificate is not in the supplied trust set.',
                )
            )
        decoded_payload = base64url_decode(str(signature['payload']))
        if decoded_payload != canonical_json(evidence):
            findings.append(
                _finding('CHECKPOINT_PAYLOAD_MISMATCH', None, 'The signed snapshot does not match the evidence.')
            )
        raw_signature = base64url_decode(str(signature['signature']))
        coordinate_size = digest.digest_size
        if len(raw_signature) != 2 * coordinate_size:
            _invalid('invalid signature length')
        der_signature = encode_dss_signature(
            int.from_bytes(raw_signature[:coordinate_size], 'big'),
            int.from_bytes(raw_signature[coordinate_size:], 'big'),
        )
        public_key = certificate.public_key()
        if not isinstance(public_key, ec.EllipticCurvePublicKey):
            _invalid('not EC', TypeError)
        public_key.verify(
            der_signature,
            f'{signature["protected"]}.{signature["payload"]}'.encode('ascii'),
            ec.ECDSA(digest),
        )
    except (InvalidSignature, KeyError, TypeError, ValueError):
        findings.append(_finding('INVALID_SNAPSHOT_SIGNATURE', None, 'The snapshot signature is invalid.'))


def verify_evidence_package(  # noqa: C901, PLR0912, PLR0915 - one linear verification walk
    document: dict[str, Any],
    trusted_certificates_pem: list[bytes] | None = None,
) -> dict[str, Any]:
    """Verify an audit evidence package, its hash chain, and its checkpoint signatures."""
    trusted_fingerprints = _trusted_fingerprints(trusted_certificates_pem or [])
    findings: list[dict[str, Any]] = []
    if set(document) != {'format', 'evidence', 'snapshot_signature'}:
        _invalid('Invalid audit evidence package.')
    if document['format'] != EVIDENCE_FORMAT:
        _invalid('Unsupported audit evidence format.')
    evidence = document['evidence']
    if not isinstance(evidence, dict) or evidence.get('scope') not in {'full', 'filtered'}:
        _invalid('Invalid audit evidence scope.')
    entries = evidence.get('entries')
    if not isinstance(entries, list):
        _invalid('Invalid audit evidence entries.', TypeError)
    scope = evidence['scope']
    complete_chain = scope == 'full'
    entry_hashes: dict[int, str] = {}
    expected_sequence = 1
    previous_hash = GENESIS_HASH
    for row in entries:
        if not isinstance(row, dict):
            findings.append(_finding('INVALID_ENTRY', None, 'An exported event is not an object.'))
            continue
        try:
            sequence = row['sequence']
            if not isinstance(sequence, int):
                _invalid('invalid sequence', TypeError)
            if complete_chain and sequence != expected_sequence:
                findings.append(
                    _finding(
                        'MISSING_ENTRY',
                        sequence,
                        f'Expected sequence {expected_sequence}, found {sequence}.',
                    )
                )
            if complete_chain and row['previous_hash'] != previous_hash:
                findings.append(
                    _finding(
                        'PREVIOUS_HASH_MISMATCH',
                        sequence,
                        'The recorded previous hash does not match the preceding exported event.',
                    )
                )
            if row['entry_hash'] != _entry_hash(row):
                findings.append(
                    _finding(
                        'HASH_MISMATCH',
                        sequence,
                        'The recorded entry hash does not match the exported event contents.',
                    )
                )
            entry_hashes[sequence] = str(row['entry_hash'])
            previous_hash = str(row['entry_hash'])
            expected_sequence = sequence + 1
        except (KeyError, TypeError, ValueError):
            findings.append(_finding('INVALID_ENTRY', None, 'An exported event is malformed.'))

    checkpoints = evidence.get('checkpoints')
    if not isinstance(checkpoints, list):
        _invalid('Invalid checkpoint evidence.', TypeError)
    certificates_document = evidence.get('certificates')
    if not isinstance(certificates_document, list):
        _invalid('Invalid checkpoint certificates.', TypeError)
    certificates: dict[str, x509.Certificate] = {}
    for certificate_document in certificates_document:
        try:
            certificate = _load_certificate(str(certificate_document['pem']))
            fingerprint = str(certificate_document['fingerprint_sha256']).upper()
        except (KeyError, TypeError, ValueError):
            findings.append(_finding('INVALID_CERTIFICATE', None, 'A checkpoint certificate is malformed.'))
            continue
        if certificate.fingerprint(hashes.SHA256()).hex().upper() != fingerprint:
            findings.append(
                _finding('CERTIFICATE_MISMATCH', None, 'A checkpoint certificate fingerprint does not match.')
            )
        certificates[fingerprint] = certificate

    previous_checkpoint_hash = ''
    previous_checkpoint_last = 0
    latest_number: int | None = None
    latest_sequence = 0
    coverage_unavailable = False
    for expected_number, checkpoint in enumerate(checkpoints, start=1):
        if not isinstance(checkpoint, dict):
            findings.append(_finding('INVALID_CHECKPOINT', None, 'A checkpoint is not an object.'))
            continue
        payload = _checkpoint_payload(checkpoint)
        if payload is None:
            findings.append(_finding('INVALID_CHECKPOINT', None, 'A checkpoint payload is malformed.'))
            continue
        if payload['checkpoint_number'] != expected_number:
            findings.append(
                _finding(
                    'CHECKPOINT_GAP',
                    payload['last_sequence'],
                    f'Expected checkpoint {expected_number}, found {payload["checkpoint_number"]}.',
                )
            )
        if payload['previous_checkpoint_hash'] != previous_checkpoint_hash and complete_chain:
            findings.append(
                _finding(
                    'CHECKPOINT_GAP',
                    payload['last_sequence'],
                    'The checkpoint does not link to the preceding checkpoint.',
                )
            )
        if not _verify_checkpoint(
            checkpoint,
            payload,
            entry_hashes,
            previous_checkpoint_last,
            complete_chain=complete_chain,
            certificates=certificates,
            trusted_fingerprints=trusted_fingerprints,
            findings=findings,
        ):
            coverage_unavailable = True
        previous_checkpoint_hash = hashlib.sha256(canonical_json(payload)).hexdigest()
        previous_checkpoint_last = payload['last_sequence']
        latest_number = payload['checkpoint_number']
        latest_sequence = payload['last_sequence']
    if not checkpoints:
        findings.append(_finding('NO_SIGNED_CHECKPOINTS', None, 'The package contains no signed checkpoints.'))
    elif scope == 'filtered' and coverage_unavailable:
        findings.append(
            _finding(
                'CHECKPOINT_COVERAGE_NOT_EXPORTED',
                None,
                'Some checkpoint head events are outside the filtered selection; coverage is not proven.',
            )
        )

    if evidence.get('entry_count') != len(entries):
        findings.append(_finding('PACKAGE_MISMATCH', None, 'The entry count does not match the exported events.'))
    first = entries[0] if entries and isinstance(entries[0], dict) else {}
    last = entries[-1] if entries and isinstance(entries[-1], dict) else {}
    expected_range = {
        'first_entry_id': first.get('id'),
        'last_entry_id': last.get('id'),
        'first_sequence': first.get('sequence'),
        'last_sequence': last.get('sequence'),
        'first_timestamp': first.get('timestamp'),
        'last_timestamp': last.get('timestamp'),
    }
    if evidence.get('range') != expected_range:
        findings.append(_finding('PACKAGE_MISMATCH', None, 'The range does not match the exported events.'))

    chain = evidence.get('chain')
    if not isinstance(chain, dict):
        _invalid('Invalid chain metadata.', TypeError)
    if chain.get('latest_checkpoint_number') != latest_number:
        findings.append(_finding('PACKAGE_MISMATCH', None, 'The latest checkpoint number does not match.'))
    if chain.get('latest_checkpoint_sequence') != latest_sequence:
        findings.append(_finding('PACKAGE_MISMATCH', None, 'The latest checkpoint sequence does not match.'))
    if complete_chain:
        last_sequence = max(entry_hashes) if entry_hashes else 0
        if chain.get('head_sequence') != last_sequence:
            findings.append(
                _finding('PACKAGE_MISMATCH', last_sequence, 'The exported chain head does not match the entries.')
            )
        if entry_hashes and chain.get('head_hash') != entry_hashes[last_sequence]:
            findings.append(
                _finding('PACKAGE_MISMATCH', last_sequence, 'The exported head hash does not match the entries.')
            )
    unsigned_entries = chain.get('unsigned_entries')
    if not isinstance(unsigned_entries, int) or unsigned_entries < 0:
        findings.append(_finding('PACKAGE_MISMATCH', None, 'Invalid unsigned entry count.'))
    else:
        if complete_chain:
            if evidence.get('complete_chain') is not True:
                findings.append(_finding('PACKAGE_MISMATCH', None, 'A full package must declare a complete chain.'))
            computed_unsigned = max(0, (max(entry_hashes) if entry_hashes else 0) - latest_sequence)
            if unsigned_entries != computed_unsigned:
                findings.append(
                    _finding('PACKAGE_MISMATCH', None, 'The unsigned entry count does not match the evidence.')
                )
        if unsigned_entries:
            findings.append(
                _finding(
                    'UNSIGNED_EVENTS',
                    chain.get('head_sequence'),
                    f'{unsigned_entries} event(s) are newer than the latest checkpoint.',
                )
            )

    _verify_snapshot(document, evidence, trusted_fingerprints, findings)
    ok = all(finding['code'] in WARNING_CODES for finding in findings)
    return {
        'ok': ok,
        'scope': scope,
        'complete_chain': complete_chain and evidence.get('complete_chain') is True,
        'entries_checked': len(entry_hashes),
        'checkpoints_checked': len(checkpoints),
        'unsigned_entries': unsigned_entries if isinstance(unsigned_entries, int) else 0,
        'findings': findings,
    }


def main() -> None:
    """Verify a downloaded evidence package using independently obtained certificates."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('export', type=Path)
    parser.add_argument(
        '--trusted-certificate',
        type=Path,
        action='append',
        default=[],
        help='PEM certificate to pin. Repeat for each signing generation.',
    )
    args = parser.parse_args()
    try:
        trusted = [path.read_bytes() for path in args.trusted_certificate]
        report = verify_evidence_package(load_json(args.export.read_bytes()), trusted)
    except (OSError, TypeError, ValueError) as error:
        parser.exit(1, f'Verification failed: {error}\n')
    print(  # noqa: T201
        f'Verified {report["entries_checked"]} entries and '
        f'{report["checkpoints_checked"]} checkpoints ({report["scope"]}).'
    )
    for finding in report['findings']:
        sequence = f' sequence {finding["sequence"]}' if finding['sequence'] is not None else ''
        print(f'{finding["code"]}{sequence}: {finding["detail"]}')  # noqa: T201
    if not report['ok']:
        sys.exit(1)


if __name__ == '__main__':
    main()
