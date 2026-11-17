# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Create portable, checkpoint-anchored audit evidence packages."""

from __future__ import annotations

import base64
import datetime as dt
import json
from typing import TYPE_CHECKING, Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from django.core.exceptions import ValidationError
from django.db import transaction
from django.utils import timezone

from management.models.audit_log import GENESIS_HASH, AuditLog
from management.models.audit_signing import AuditLogCheckpoint, AuditSigningConfig
from management.models.traceability import TraceabilityCredentialModel
from management.services.traceability_signing import TraceabilityCredentialService
from util.audit_log_export import (
    EVIDENCE_FORMAT,
    base64url_encode,
    canonical_json,
    certificate_signature_algorithm,
    encode_json,
)

if TYPE_CHECKING:
    from django.db.models import QuerySet

# shortcut: snapshots buffer up to 10,000 entries; stream evidence packages if larger exports are needed.
MAX_EXPORT_ENTRIES = 10_000
MAX_EXPORT_CHECKPOINTS = 10_000


def _export_timestamp(value: dt.datetime) -> str:
    """Return the exact UTC representation used by the audit entry hash."""
    if timezone.is_naive(value):
        value = timezone.make_aware(value, dt.UTC)
    return value.astimezone(dt.UTC).isoformat(timespec='microseconds')


def _checkpoint_document(checkpoint: AuditLogCheckpoint) -> dict[str, Any]:
    """Export only the signed payload and signature; all metadata lives inside the payload."""
    return {
        'payload': json.loads(checkpoint.payload),
        'signature': base64.b64encode(bytes(checkpoint.signature)).decode('ascii'),
    }


def _checkpoint_certificates(checkpoints: list[AuditLogCheckpoint]) -> list[dict[str, str]]:
    """Return each distinct signing certificate once, keyed by fingerprint in the payload."""
    certificates: dict[str, dict[str, str]] = {}
    for checkpoint in checkpoints:
        certificate = checkpoint.traceability_generation.credential.certificate_or_error
        fingerprint = certificate.sha256_fingerprint.upper()
        if fingerprint not in certificates:
            certificates[fingerprint] = {
                'fingerprint_sha256': fingerprint,
                'pem': certificate.get_certificate_serializer().as_pem().decode('ascii'),
            }
    return list(certificates.values())


def _lock_snapshot_credential() -> tuple[TraceabilityCredentialModel, dict[str, str]]:
    """Lock the configured snapshot signer and return its certificate document."""
    config = AuditSigningConfig.objects.filter(pk=1, enabled=True).first()
    if config is None or config.traceability_credential_id is None:
        msg = 'Filtered evidence exports require audit signing to be configured.'
        raise ValidationError(msg)
    logical = TraceabilityCredentialModel.objects.select_for_update().get(pk=config.traceability_credential_id)
    if not logical.is_usable or logical.current_generation is None:
        msg = 'The configured audit signing credential is not currently usable.'
        raise ValidationError(msg)
    certificate = logical.current_generation.credential.certificate_or_error
    return logical, {
        'fingerprint_sha256': certificate.sha256_fingerprint.upper(),
        'pem': certificate.get_certificate_serializer().as_pem().decode('ascii'),
    }


def _snapshot_signature(evidence: dict[str, Any], logical: TraceabilityCredentialModel) -> dict[str, str]:
    """Sign a filtered evidence snapshot with the already locked signing credential."""
    generation = logical.current_generation
    if generation is None:  # pragma: no cover - _lock_snapshot_credential rejects this
        msg = 'The configured audit signing credential is not currently usable.'
        raise ValidationError(msg)
    certificate = generation.credential.certificate_or_error.get_certificate_serializer().as_crypto()
    digest, algorithm = certificate_signature_algorithm(certificate)
    protected = base64url_encode(
        encode_json(
            {
                'alg': algorithm,
                'cty': 'application/json',
                'x5c': [base64.b64encode(certificate.public_bytes(serialization.Encoding.DER)).decode('ascii')],
            }
        )
    )
    encoded_payload = base64url_encode(canonical_json(evidence))
    signing_input = f'{protected}.{encoded_payload}'.encode('ascii')
    signed = TraceabilityCredentialService.sign(traceability_credential=logical, data=signing_input)
    if signed.generation_id != generation.pk or signed.certificate_id != generation.credential.certificate_id:
        msg = 'The signing generation changed while the export snapshot was being created.'
        raise ValidationError(msg)
    r, s = decode_dss_signature(signed.signature)
    raw_signature = r.to_bytes(digest.digest_size, 'big') + s.to_bytes(digest.digest_size, 'big')
    return {
        'protected': protected,
        'payload': encoded_payload,
        'signature': base64url_encode(raw_signature),
    }


@transaction.atomic
def create_evidence_export(entries: QuerySet[AuditLog], filters: dict[str, str]) -> dict[str, Any]:
    """Capture a verifiable snapshot of the selected entries and the full checkpoint history."""
    scope = 'full' if not filters else 'filtered'
    checkpoint_at_start = (
        AuditLogCheckpoint.objects.order_by('-checkpoint_number').values('last_sequence', 'head_hash').first()
    )
    latest_checkpoint_sequence_at_start = checkpoint_at_start['last_sequence'] if checkpoint_at_start else 0
    head = AuditLog.objects.order_by('-sequence').only('sequence', 'entry_hash').first()
    head_sequence = head.sequence if head is not None else 0
    head_hash = head.entry_hash if head is not None else GENESIS_HASH
    if latest_checkpoint_sequence_at_start > head_sequence:
        msg = (
            'The audit log head is older than the latest signed checkpoint. '
            'The log may be truncated; verify integrity before exporting.'
        )
        raise ValidationError(msg)
    if scope == 'full' and checkpoint_at_start is not None:
        head_sequence = checkpoint_at_start['last_sequence']
        head_hash = checkpoint_at_start['head_hash']
    selected = (
        entries.filter(sequence__lte=head_sequence)
        .order_by('sequence')
        .values(
            'id',
            'sequence',
            'previous_hash',
            'entry_hash',
            'timestamp',
            'operation_type',
            'target_type',
            'target_object_id',
            'target_display',
            'actor_label',
            'details',
        )[: MAX_EXPORT_ENTRIES + 1]
    )
    rows: list[dict[str, Any]] = [{**row, 'timestamp': _export_timestamp(row['timestamp'])} for row in selected]
    if len(rows) > MAX_EXPORT_ENTRIES:
        msg = f'Export limited to {MAX_EXPORT_ENTRIES:,} entries. Narrow the audit log filters.'
        raise ValidationError(msg)

    checkpoints = list(
        AuditLogCheckpoint.objects.filter(last_sequence__lte=head_sequence)
        .select_related(
            'traceability_credential',
            'traceability_generation__credential__certificate',
        )
        .order_by('checkpoint_number')[: MAX_EXPORT_CHECKPOINTS + 1]
    )
    if len(checkpoints) > MAX_EXPORT_CHECKPOINTS:
        msg = f'Evidence export limited to {MAX_EXPORT_CHECKPOINTS:,} checkpoints.'
        raise ValidationError(msg)
    checkpoint_documents = [_checkpoint_document(checkpoint) for checkpoint in checkpoints]
    latest_checkpoint = checkpoints[-1] if checkpoints else None
    certificates = _checkpoint_certificates(checkpoints)
    snapshot_credential: TraceabilityCredentialModel | None = None
    if scope == 'filtered':
        snapshot_credential, snapshot_certificate = _lock_snapshot_credential()
        if snapshot_certificate['fingerprint_sha256'] not in {
            certificate['fingerprint_sha256'] for certificate in certificates
        }:
            certificates.append(snapshot_certificate)
    evidence = {
        'scope': scope,
        'complete_chain': scope == 'full',
        'exported_at': _export_timestamp(timezone.now()),
        'filters': filters,
        'range': {
            'first_entry_id': rows[0]['id'] if rows else None,
            'last_entry_id': rows[-1]['id'] if rows else None,
            'first_sequence': rows[0]['sequence'] if rows else None,
            'last_sequence': rows[-1]['sequence'] if rows else None,
            'first_timestamp': rows[0]['timestamp'] if rows else None,
            'last_timestamp': rows[-1]['timestamp'] if rows else None,
        },
        'entry_count': len(rows),
        'entries': rows,
        'chain': {
            'head_sequence': head_sequence,
            'head_hash': head_hash,
            'latest_checkpoint_number': latest_checkpoint.checkpoint_number if latest_checkpoint else None,
            'latest_checkpoint_sequence': latest_checkpoint.last_sequence if latest_checkpoint else 0,
            'unsigned_entries': max(0, head_sequence - (latest_checkpoint.last_sequence if latest_checkpoint else 0)),
        },
        'checkpoints': checkpoint_documents,
        'certificates': certificates,
    }
    snapshot_signature = _snapshot_signature(evidence, snapshot_credential) if snapshot_credential is not None else None
    return {
        'format': EVIDENCE_FORMAT,
        'evidence': evidence,
        'snapshot_signature': snapshot_signature,
    }
