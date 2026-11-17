# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Verification of the audit event hash chain and signed checkpoints."""

from __future__ import annotations

import datetime as dt
import json
from dataclasses import dataclass
from datetime import timedelta
from enum import StrEnum
from typing import Any

from django.utils import timezone

from management.models.audit_log import GENESIS_HASH, AuditLog
from management.models.audit_signing import AuditLogCheckpoint, AuditSigningConfig
from management.services.audit_signing import CHECKPOINT_CONTEXT, count_pending_business_events
from management.services.traceability_signing import TraceabilityCredentialService

VERIFY_BATCH_SIZE = 1000


class AuditFindingCode(StrEnum):
    """Stable machine-readable integrity findings."""

    MISSING_ENTRY = 'MISSING_ENTRY'
    HASH_MISMATCH = 'HASH_MISMATCH'
    PREVIOUS_HASH_MISMATCH = 'PREVIOUS_HASH_MISMATCH'
    CHAIN_TRUNCATED = 'CHAIN_TRUNCATED'
    CHECKPOINT_GAP = 'CHECKPOINT_GAP'
    CHECKPOINT_PAYLOAD_MISMATCH = 'CHECKPOINT_PAYLOAD_MISMATCH'
    CHECKPOINT_HEAD_MISMATCH = 'CHECKPOINT_HEAD_MISMATCH'
    INVALID_CHECKPOINT_SIGNATURE = 'INVALID_CHECKPOINT_SIGNATURE'
    SIGNING_NOT_CONFIGURED = 'SIGNING_NOT_CONFIGURED'
    NO_SIGNED_CHECKPOINTS = 'NO_SIGNED_CHECKPOINTS'
    UNSIGNED_EVENTS = 'UNSIGNED_EVENTS'


WARNING_CODES = frozenset(
    {
        AuditFindingCode.SIGNING_NOT_CONFIGURED,
        AuditFindingCode.NO_SIGNED_CHECKPOINTS,
        AuditFindingCode.UNSIGNED_EVENTS,
    }
)


@dataclass(frozen=True, slots=True)
class AuditFinding:
    """One integrity finding with a stable code and sequence context."""

    code: AuditFindingCode
    sequence: int | None = None
    detail: str = ''


@dataclass(frozen=True, slots=True)
class AuditVerificationReport:
    """Result of verifying the complete event chain and all retained checkpoints."""

    entries_checked: int
    checkpoints_checked: int
    unsigned_entries: int
    findings: tuple[AuditFinding, ...]

    @property
    def ok(self) -> bool:
        """Return whether all fatal checks passed; missing signatures and unsigned events are warnings."""
        return all(finding.code in WARNING_CODES for finding in self.findings)


def _verify_entries(checkpoint_sequences: set[int]) -> tuple[list[AuditFinding], int, int, dict[int, str]]:
    """Verify event ordering and hashes, retaining hashes needed by checkpoints."""
    findings: list[AuditFinding] = []
    previous_hash = GENESIS_HASH
    expected_sequence = 1
    entries_checked = 0
    max_sequence = 0
    entry_hashes: dict[int, str] = {}
    entries = (
        AuditLog.objects.only(
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
        )
        .order_by('sequence')
        .iterator(chunk_size=VERIFY_BATCH_SIZE)
    )
    for entry in entries:
        entries_checked += 1
        max_sequence = entry.sequence
        if entry.sequence != expected_sequence:
            findings.append(
                AuditFinding(
                    AuditFindingCode.MISSING_ENTRY,
                    entry.sequence,
                    f'Expected sequence {expected_sequence}, found {entry.sequence}.',
                )
            )
            expected_sequence = entry.sequence
        if entry.previous_hash != previous_hash:
            findings.append(
                AuditFinding(
                    AuditFindingCode.PREVIOUS_HASH_MISMATCH,
                    entry.sequence,
                    'The recorded previous hash does not match the preceding entry.',
                )
            )
        if entry.entry_hash != entry.calculate_entry_hash():
            findings.append(
                AuditFinding(
                    AuditFindingCode.HASH_MISMATCH,
                    entry.sequence,
                    'The recorded entry hash does not match the event contents.',
                )
            )
        if entry.sequence in checkpoint_sequences:
            entry_hashes[entry.sequence] = entry.entry_hash
        previous_hash = entry.entry_hash
        expected_sequence += 1
    return findings, entries_checked, max_sequence, entry_hashes


def verify_audit_chain() -> AuditVerificationReport:
    """Verify event hashes, ordering, checkpoint coverage, and every checkpoint signature."""
    checkpoints = list(
        AuditLogCheckpoint.objects.select_related(
            'traceability_credential',
            'traceability_generation__credential__certificate',
            'traceability_generation__traceability_credential',
        ).order_by('checkpoint_number')
    )
    checkpoint_sequences = {checkpoint.last_sequence for checkpoint in checkpoints if checkpoint.last_sequence > 0}
    findings, entries_checked, max_sequence, entry_hashes = _verify_entries(checkpoint_sequences)

    previous_checkpoint_hash = ''
    previous_checkpoint_last = 0
    checkpoints_checked = 0
    for expected_number, checkpoint in enumerate(checkpoints, start=1):
        checkpoints_checked += 1
        if checkpoint.checkpoint_number != expected_number:
            findings.append(
                AuditFinding(
                    AuditFindingCode.CHECKPOINT_GAP,
                    checkpoint.last_sequence,
                    f'Expected checkpoint {expected_number}, found {checkpoint.checkpoint_number}.',
                )
            )
        if checkpoint.last_sequence > max_sequence:
            findings.append(
                AuditFinding(
                    AuditFindingCode.CHAIN_TRUNCATED,
                    checkpoint.last_sequence,
                    'The checkpoint covers entries that are no longer present.',
                )
            )
        if checkpoint.previous_checkpoint_hash != previous_checkpoint_hash:
            findings.append(
                AuditFinding(
                    AuditFindingCode.CHECKPOINT_GAP,
                    checkpoint.last_sequence,
                    'The checkpoint does not link to the preceding checkpoint.',
                )
            )
        _verify_checkpoint(checkpoint, entry_hashes, previous_checkpoint_last, findings)
        previous_checkpoint_hash = checkpoint.checkpoint_hash
        previous_checkpoint_last = checkpoint.last_sequence

    config = AuditSigningConfig.objects.filter(pk=1).first()
    signing_findings, signing_ready = _signing_findings(
        config=config,
        has_checkpoints=bool(checkpoints),
        max_sequence=max_sequence,
    )
    findings.extend(signing_findings)
    unsigned_entries = max(0, max_sequence - previous_checkpoint_last)
    business_unsigned_entries = count_pending_business_events(previous_checkpoint_last)
    if business_unsigned_entries and signing_ready and checkpoints and config is not None:
        last_checkpoint = checkpoints[-1]
        due_by_count = business_unsigned_entries >= config.checkpoint_event_interval
        due_by_time = bool(
            config.checkpoint_time_interval_minutes
            and timezone.now() - last_checkpoint.signed_at
            >= timedelta(minutes=config.checkpoint_time_interval_minutes)
        )
        if due_by_count or due_by_time:
            findings.append(
                AuditFinding(
                    AuditFindingCode.UNSIGNED_EVENTS,
                    max_sequence,
                    f'{business_unsigned_entries} event(s) are waiting for a signed checkpoint '
                    'and the configured interval is due.',
                )
            )
    return AuditVerificationReport(
        entries_checked=entries_checked,
        checkpoints_checked=checkpoints_checked,
        unsigned_entries=unsigned_entries,
        findings=tuple(findings),
    )


def _signing_findings(
    *,
    config: AuditSigningConfig | None,
    has_checkpoints: bool,
    max_sequence: int,
) -> tuple[list[AuditFinding], bool]:
    """Report unusable signing and return whether checkpoints are currently enforceable."""
    if config is None:
        return [
            AuditFinding(
                AuditFindingCode.SIGNING_NOT_CONFIGURED,
                None,
                'Audit checkpoint signing is not configured.',
            )
        ], False
    if not config.enabled:
        return [
            AuditFinding(
                AuditFindingCode.SIGNING_NOT_CONFIGURED,
                None,
                'Audit checkpoint signing is disabled; the hash chain has no signed checkpoints.',
            )
        ], False
    if config.traceability_credential_id is None:
        return [
            AuditFinding(
                AuditFindingCode.SIGNING_NOT_CONFIGURED,
                None,
                'No Traceability Credential is configured for audit signing.',
            )
        ], False
    credential = config.traceability_credential
    if credential is None or not credential.is_usable:
        return [
            AuditFinding(
                AuditFindingCode.SIGNING_NOT_CONFIGURED,
                None,
                'The configured Traceability Credential is not currently usable.',
            )
        ], False
    if not has_checkpoints:
        return [
            AuditFinding(
                AuditFindingCode.NO_SIGNED_CHECKPOINTS,
                max_sequence or None,
                'No signed checkpoint exists yet; the hash chain is not cryptographically anchored.',
            )
        ], True
    return [], True


def _verify_checkpoint(
    checkpoint: AuditLogCheckpoint,
    entry_hashes: dict[int, str],
    previous_checkpoint_last: int,
    findings: list[AuditFinding],
) -> None:
    """Verify coverage and the exact signed checkpoint payload."""
    if checkpoint.last_sequence == 0:
        if (
            checkpoint.checkpoint_number != 1
            or checkpoint.first_sequence != 1
            or checkpoint.entry_count != 0
            or checkpoint.head_hash != GENESIS_HASH
        ):
            findings.append(
                AuditFinding(
                    AuditFindingCode.CHECKPOINT_PAYLOAD_MISMATCH,
                    checkpoint.last_sequence,
                    'The genesis checkpoint has inconsistent coverage.',
                )
            )
    else:
        expected_first = previous_checkpoint_last + 1
        if checkpoint.first_sequence != expected_first:
            findings.append(
                AuditFinding(
                    AuditFindingCode.CHECKPOINT_GAP,
                    checkpoint.last_sequence,
                    f'Expected first sequence {expected_first}, found {checkpoint.first_sequence}.',
                )
            )
        expected_count = checkpoint.last_sequence - checkpoint.first_sequence + 1
        if checkpoint.entry_count != expected_count:
            findings.append(
                AuditFinding(
                    AuditFindingCode.CHECKPOINT_PAYLOAD_MISMATCH,
                    checkpoint.last_sequence,
                    'The checkpoint entry count does not match its range.',
                )
            )
        if entry_hashes.get(checkpoint.last_sequence) != checkpoint.head_hash:
            findings.append(
                AuditFinding(
                    AuditFindingCode.CHECKPOINT_HEAD_MISMATCH,
                    checkpoint.last_sequence,
                    'The checkpoint head hash does not match the event at that sequence.',
                )
            )

    try:
        payload = json.loads(checkpoint.payload)
    except (TypeError, ValueError):
        findings.append(
            AuditFinding(
                AuditFindingCode.CHECKPOINT_PAYLOAD_MISMATCH,
                checkpoint.last_sequence,
                'The checkpoint payload is not valid JSON.',
            )
        )
        return
    _verify_payload_fields(checkpoint, payload, findings)
    try:
        result = TraceabilityCredentialService.verify(
            generation=checkpoint.traceability_generation,
            data=checkpoint.payload.encode('utf-8'),
            signature=bytes(checkpoint.signature),
        )
    except Exception:  # noqa: BLE001 - verification must report, not raise
        findings.append(
            AuditFinding(
                AuditFindingCode.INVALID_CHECKPOINT_SIGNATURE,
                checkpoint.last_sequence,
                'The checkpoint signature could not be verified.',
            )
        )
        return
    if (
        not result.valid
        or result.certificate_fingerprint_sha256 != checkpoint.certificate_fingerprint_sha256
        or result.algorithm != checkpoint.signature_algorithm
    ):
        findings.append(
            AuditFinding(
                AuditFindingCode.INVALID_CHECKPOINT_SIGNATURE,
                checkpoint.last_sequence,
                'The checkpoint signature or signing generation is invalid.',
            )
        )


def _verify_payload_fields(
    checkpoint: AuditLogCheckpoint,
    payload: Any,
    findings: list[AuditFinding],
) -> None:
    """Compare the signed payload with the duplicated database columns."""
    expected = {
        'v': 1,
        'checkpoint_number': checkpoint.checkpoint_number,
        'first_sequence': checkpoint.first_sequence,
        'last_sequence': checkpoint.last_sequence,
        'entry_count': checkpoint.entry_count,
        'head_hash': checkpoint.head_hash,
        'previous_checkpoint_hash': checkpoint.previous_checkpoint_hash,
    }
    signer = payload.get('signer') if isinstance(payload, dict) else None
    generation = checkpoint.traceability_generation
    expected_signed_at = checkpoint.signed_at
    if expected_signed_at.tzinfo is None:
        expected_signed_at = expected_signed_at.replace(tzinfo=dt.UTC)
    matches = (
        isinstance(payload, dict)
        and payload.get('context') == CHECKPOINT_CONTEXT
        and all(payload.get(key) == value for key, value in expected.items())
        and isinstance(signer, dict)
        and signer.get('credential_id') == checkpoint.traceability_credential_id
        and signer.get('credential_name') == checkpoint.traceability_credential.name
        and signer.get('generation_id') == checkpoint.traceability_generation_id
        and signer.get('generation_number') == generation.generation_number
        and signer.get('certificate_fingerprint_sha256') == checkpoint.certificate_fingerprint_sha256
    )
    if matches:
        try:
            signed_at = dt.datetime.fromisoformat(payload['signed_at'])
        except (KeyError, TypeError, ValueError):
            matches = False
        else:
            if signed_at.tzinfo is None:
                signed_at = signed_at.replace(tzinfo=dt.UTC)
            matches = signed_at == expected_signed_at
    if not matches:
        findings.append(
            AuditFinding(
                AuditFindingCode.CHECKPOINT_PAYLOAD_MISMATCH,
                checkpoint.last_sequence,
                'The signed payload does not match the stored checkpoint columns.',
            )
        )
