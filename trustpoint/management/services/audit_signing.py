# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Checkpoint signing for the audit hash chain."""

from __future__ import annotations

import datetime as dt
import logging
from contextlib import contextmanager
from contextvars import ContextVar
from datetime import timedelta
from typing import TYPE_CHECKING, Any

from django.core.exceptions import ValidationError
from django.db import IntegrityError, OperationalError, transaction
from django.utils import timezone
from django_q.models import Schedule
from django_q.tasks import schedule

from management.models.audit_log import GENESIS_HASH, AuditLog
from management.models.audit_signing import AuditLogCheckpoint, AuditSigningConfig
from management.models.traceability import TraceabilityCredentialModel
from management.services.traceability_signing import TraceabilityCredentialService
from util.audit_log_export import canonical_json

if TYPE_CHECKING:
    from collections.abc import Iterator

    from management.models.traceability import TraceabilityCredentialGenerationModel
    from management.services.traceability_signing import TraceabilitySigningResult

logger = logging.getLogger('trustpoint.audit.signing')

CHECKPOINT_CONTEXT = 'trustpoint:audit-checkpoint:v1'
SIGNING_FAILURE_BACKOFF = timedelta(seconds=60)
SCHEDULE_NAME = 'trustpoint-audit-checkpoint'
DEFAULT_SCHEDULE_INTERVAL_MINUTES = 5
MAX_ERROR_LENGTH = 1000

_CHECKPOINT_SIGNING_ACTIVE: ContextVar[bool] = ContextVar('audit_checkpoint_signing', default=False)


def checkpoint_signing_active() -> bool:
    """Return whether this process is currently creating a checkpoint signature."""
    return _CHECKPOINT_SIGNING_ACTIVE.get()


@contextmanager
def _checkpoint_signing_guard() -> Iterator[None]:
    """Prevent audit writes made by checkpoint signing from triggering another checkpoint."""
    token = _CHECKPOINT_SIGNING_ACTIVE.set(True)
    try:
        yield
    finally:
        _CHECKPOINT_SIGNING_ACTIVE.reset(token)


def _latest_checkpoint() -> AuditLogCheckpoint | None:
    return AuditLogCheckpoint.objects.order_by('-checkpoint_number').first()


def _chain_head() -> AuditLog | None:
    return AuditLog.objects.order_by('-sequence').only('sequence', 'entry_hash').first()


def count_pending_business_events(sequence: int) -> int:
    """Count user events, excluding the audit records emitted by checkpoint signing itself."""
    return (
        AuditLog.objects.filter(sequence__gt=sequence)
        .exclude(operation_type=AuditLog.OperationType.AUDIT_CHECKPOINT_SIGNED)
        # The key check keeps rows with missing JSON keys eligible on both supported databases.
        .exclude(details__has_key='audit_checkpoint_signing', details__audit_checkpoint_signing=True)
        .count()
    )


def _is_due(  # noqa: PLR0911 - explicit policy branches are easier to audit
    config: AuditSigningConfig,
    head: AuditLog | None,
    latest: AuditLogCheckpoint | None,
) -> bool:
    """Return whether new entries justify a checkpoint under the configured policy."""
    if head is None:
        return False
    if latest is None:
        return True
    if latest.last_sequence >= head.sequence:
        return False
    pending = count_pending_business_events(latest.last_sequence)
    if pending == 0:
        return False
    if pending >= config.checkpoint_event_interval:
        return True
    if config.checkpoint_time_interval_minutes:
        elapsed = timezone.now() - latest.signed_at
        return elapsed >= timedelta(minutes=config.checkpoint_time_interval_minutes)
    return False


def maybe_sign_checkpoint() -> AuditLogCheckpoint | None:
    """Sign a checkpoint when policy requires one, without raising to the caller."""
    if checkpoint_signing_active():
        return None
    config: AuditSigningConfig | None = None
    try:
        config = AuditSigningConfig.objects.filter(pk=1, enabled=True).first()
        if config is None or config.traceability_credential_id is None:
            return None
        if (
            config.last_signing_error
            and config.last_signing_attempt_at is not None
            and timezone.now() - config.last_signing_attempt_at < SIGNING_FAILURE_BACKOFF
        ):
            return None
        if not _is_due(config, _chain_head(), _latest_checkpoint()):
            return None
        return _sign_checkpoint(config.pk, respect_policy=True)
    except Exception as error:  # noqa: BLE001 - auditing must not break request handling after commit
        if config is not None:
            _record_failure(config.pk, error)
        else:
            logger.warning('Audit checkpoint signing failed before configuration was loaded: %s', error)
        return None


def create_checkpoint(*, config: AuditSigningConfig | None = None) -> AuditLogCheckpoint | None:
    """Sign the current unsigned range, or an empty genesis checkpoint when no events exist."""
    config = config or AuditSigningConfig.objects.filter(pk=1, enabled=True).first()
    if config is None or not config.enabled:
        message = 'Audit checkpoint signing is not enabled.'
        raise ValidationError(message)
    return _sign_checkpoint(config.pk)


def _sign_checkpoint(  # noqa: C901, PLR0915 - keep checkpoint writes in one transaction
    config_pk: int, *, respect_policy: bool = False
) -> AuditLogCheckpoint | None:
    """Serialize checkpoint creation and sign the exact canonical payload."""
    with transaction.atomic():
        config = AuditSigningConfig.objects.select_for_update().get(pk=config_pk)
        if not config.enabled:
            message = 'Audit checkpoint signing is not enabled.'
            raise ValidationError(message)
        if config.traceability_credential_id is None:
            message = 'Select a Traceability Credential.'
            raise ValidationError(message)
        # Lock before reading the generation. Rotation also locks this row, so the
        # metadata in the signed payload always names the key that creates the signature.
        logical = TraceabilityCredentialModel.objects.select_for_update().get(
            pk=config.traceability_credential_id
        )
        _validate_config(config, logical)
        latest = AuditLogCheckpoint.objects.select_for_update().order_by('-checkpoint_number').first()
        head = _chain_head()
        target_sequence = head.sequence if head is not None else 0
        if respect_policy and not _is_due(config, head, latest):
            return None
        if latest is not None:
            if latest.last_sequence >= target_sequence:
                return None
            if count_pending_business_events(latest.last_sequence) == 0:
                # Do not create checkpoints solely for signing-event records.
                return None
            checkpoint_number = latest.checkpoint_number + 1
            first_sequence = latest.last_sequence + 1
            previous_checkpoint_hash = latest.checkpoint_hash
        else:
            checkpoint_number = 1
            first_sequence = 1
            previous_checkpoint_hash = ''

        if target_sequence == 0:
            entry_count = 0
            head_hash = GENESIS_HASH
        else:
            assert head is not None  # noqa: S101 - target_sequence is derived from head
            entry_count = target_sequence - first_sequence + 1
            head_hash = head.entry_hash
        signed_at = timezone.now()
        generation = logical.current_generation
        if generation is None:  # pragma: no cover - _validate_config rejects this
            message = 'The selected Traceability Credential has no active generation.'
            raise ValidationError(message)
        payload = _checkpoint_payload(
            checkpoint_number=checkpoint_number,
            first_sequence=first_sequence,
            last_sequence=target_sequence,
            entry_count=entry_count,
            head_hash=head_hash,
            previous_checkpoint_hash=previous_checkpoint_hash,
            signed_at=signed_at,
            credential_id=logical.pk,
            credential_name=logical.name,
            generation=generation,
        )
        payload_bytes = canonical_json(payload)
        with _checkpoint_signing_guard():
            result = TraceabilityCredentialService.sign(
                traceability_credential=logical,
                data=payload_bytes,
            )
        _require_signing_result(result, logical.pk, generation)
        try:
            with transaction.atomic():
                checkpoint = AuditLogCheckpoint.objects.create(
                    checkpoint_number=checkpoint_number,
                    first_sequence=first_sequence,
                    last_sequence=target_sequence,
                    entry_count=entry_count,
                    head_hash=head_hash,
                    previous_checkpoint_hash=previous_checkpoint_hash,
                    payload=payload_bytes.decode('utf-8'),
                    signature=result.signature,
                    signature_algorithm=result.algorithm,
                    traceability_credential_id=result.traceability_credential_id,
                    traceability_generation_id=result.generation_id,
                    certificate_fingerprint_sha256=result.certificate_fingerprint_sha256,
                    signed_at=signed_at,
                )
        except IntegrityError:
            # Another process signed the same range first.
            return None
        config.last_signing_attempt_at = signed_at
        config.last_signing_error = ''
        config.save(update_fields=['last_signing_attempt_at', 'last_signing_error', 'updated_at'])
        if config.checkpoint_time_interval_minutes:
            Schedule.objects.filter(name=SCHEDULE_NAME).update(
                next_run=signed_at + timedelta(minutes=config.checkpoint_time_interval_minutes)
            )
        transaction.on_commit(lambda: _log_checkpoint_signed(checkpoint.pk))
        return checkpoint


def _validate_config(config: AuditSigningConfig, logical: TraceabilityCredentialModel) -> None:
    """Revalidate usability after locking the credential and reading its generation."""
    if not config.enabled:
        message = 'Audit checkpoint signing is not enabled.'
        raise ValidationError(message)
    if not logical.is_usable:
        message = 'The configured Traceability Credential is not currently usable.'
        raise ValidationError(message)


def _require_signing_result(
    result: TraceabilitySigningResult,
    logical_id: int,
    generation: TraceabilityCredentialGenerationModel,
) -> None:
    """Reject a backend result that no longer matches the locked signing generation."""
    if (
        result.traceability_credential_id != logical_id
        or result.generation_id != generation.pk
        or result.certificate_id != generation.credential.certificate_id
    ):
        message = 'The signing generation changed while the audit checkpoint was being created.'
        raise ValidationError(message)


def _checkpoint_payload(  # noqa: PLR0913 - explicit signing fields keep the payload auditable
    *,
    checkpoint_number: int,
    first_sequence: int,
    last_sequence: int,
    entry_count: int,
    head_hash: str,
    previous_checkpoint_hash: str,
    signed_at: dt.datetime,
    credential_id: int,
    credential_name: str,
    generation: TraceabilityCredentialGenerationModel,
) -> dict[str, Any]:
    certificate = generation.credential.certificate_or_error
    return {
        'v': 1,
        'context': CHECKPOINT_CONTEXT,
        'checkpoint_number': checkpoint_number,
        'first_sequence': first_sequence,
        'last_sequence': last_sequence,
        'entry_count': entry_count,
        'head_hash': head_hash,
        'previous_checkpoint_hash': previous_checkpoint_hash,
        'signed_at': signed_at.isoformat(),
        'signer': {
            'credential_id': credential_id,
            'credential_name': credential_name,
            'generation_id': generation.pk,
            'generation_number': generation.generation_number,
            'certificate_fingerprint_sha256': certificate.sha256_fingerprint,
        },
    }


def _record_failure(config_pk: int, error: Exception) -> None:
    """Persist a bounded diagnostic and leave the unsigned range for the next retry."""
    message = f'{type(error).__name__}: {error}'[:MAX_ERROR_LENGTH]
    try:
        AuditSigningConfig.objects.filter(pk=config_pk).update(
            last_signing_attempt_at=timezone.now(),
            last_signing_error=message,
        )
    except Exception:
        logger.warning('Could not record audit signing failure.', exc_info=True)
    logger.warning('Audit checkpoint signing failed: %s', message)


def _log_checkpoint_signed(checkpoint_pk: int) -> None:
    """Record the signing event without letting it trigger another checkpoint."""
    try:
        checkpoint = AuditLogCheckpoint.objects.select_related(
            'traceability_credential',
            'traceability_generation',
        ).get(pk=checkpoint_pk)
        if checkpoint.last_sequence == 0:
            coverage = 'genesis'
        else:
            coverage = f'sequences {checkpoint.first_sequence}-{checkpoint.last_sequence}'
        with _checkpoint_signing_guard():
            AuditLog.create_entry(
                operation_type=AuditLog.OperationType.AUDIT_CHECKPOINT_SIGNED,
                target=checkpoint,
                target_display=f'Audit checkpoint {checkpoint.checkpoint_number} ({coverage})',
                actor=None,
                details={
                    'checkpoint_number': checkpoint.checkpoint_number,
                    'first_sequence': checkpoint.first_sequence,
                    'last_sequence': checkpoint.last_sequence,
                    'entry_count': checkpoint.entry_count,
                    'head_hash': checkpoint.head_hash,
                    'traceability_credential_id': checkpoint.traceability_credential_id,
                    'traceability_credential_name': checkpoint.traceability_credential.name,
                    'generation_id': checkpoint.traceability_generation_id,
                    'generation_number': checkpoint.traceability_generation.generation_number,
                    'signature_algorithm': checkpoint.signature_algorithm,
                    'certificate_fingerprint_sha256': checkpoint.certificate_fingerprint_sha256,
                },
            )
    except Exception:
        logger.warning('Could not record the audit checkpoint signing event.', exc_info=True)


def sync_signing_schedule(*, enabled: bool, time_interval_minutes: int | None) -> None:
    """Create or remove the retry schedule using the configured maximum interval."""
    interval_minutes = time_interval_minutes or DEFAULT_SCHEDULE_INTERVAL_MINUTES
    try:
        with transaction.atomic():
            # Serialize timer replacement with checkpoint creation, which locks the same row first.
            AuditSigningConfig.objects.select_for_update().get(pk=1)
            next_run = timezone.now()
            latest = _latest_checkpoint() if enabled and time_interval_minutes else None
            if latest is not None:
                next_run = max(next_run, latest.signed_at + timedelta(minutes=interval_minutes))
            Schedule.objects.filter(name=SCHEDULE_NAME).delete()
            if enabled:
                schedule(
                    'management.tasks.sign_audit_checkpoint',
                    name=SCHEDULE_NAME,
                    schedule_type=Schedule.MINUTES,
                    minutes=interval_minutes,
                    next_run=next_run,
                    repeats=-1,
                )
    except (OperationalError, RuntimeError, ValueError):
        logger.warning('Could not synchronize the audit checkpoint retry schedule.', exc_info=True)
