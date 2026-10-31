# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Deadlines and rejection handling for explicit CMP certificate confirmation."""

from __future__ import annotations

import logging
from contextlib import contextmanager
from datetime import timedelta
from typing import TYPE_CHECKING

from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from django.db import transaction
from django.utils import timezone

from cmp.models import CmpTransactionModel
from devices.secrets import invalidate_onboarding_secrets
from onboarding.models import OnboardingConfigModel
from pki.services.revocation import revoke_certificate

if TYPE_CHECKING:
    from collections.abc import Iterator
    from datetime import datetime

logger = logging.getLogger(__name__)


def start_confirmation_wait(record: CmpTransactionModel) -> None:
    """Snapshot the timeout policy at issuance; retransmissions must not extend it."""
    if record.implicit_confirm or record.confirmation_deadline is not None:
        return
    seconds = int(settings.TRUSTPOINT_CMP_CONFIRMATION_TIMEOUT_SECONDS)
    policy = settings.TRUSTPOINT_CMP_CONFIRMATION_TIMEOUT_POLICY
    if seconds <= 0 or policy not in {'revoke', 'log'}:
        msg = 'CMP confirmation requires a positive timeout and a revoke or log timeout policy.'
        raise ImproperlyConfigured(msg)
    record.confirmation_deadline = timezone.now() + timedelta(seconds=seconds)
    record.confirmation_timeout_policy = policy


@contextmanager
def locked_confirmation(transaction_pk: int) -> Iterator[tuple[CmpTransactionModel, OnboardingConfigModel | None]]:
    """Lock bootstrap configuration before the transaction, matching issuance lock order."""
    with transaction.atomic():
        record = CmpTransactionModel.objects.select_related('device').get(pk=transaction_pk)
        config_id = record.device.onboarding_config_id if record.device else None
        config = OnboardingConfigModel.objects.select_for_update().get(pk=config_id) if config_id is not None else None
        record = CmpTransactionModel.objects.select_for_update().get(pk=transaction_pk)
        yield record, config


def confirmation_is_due(record: CmpTransactionModel, now: datetime) -> bool:
    """Return whether an issued, unconfirmed transaction has reached its deadline."""
    return bool(
        record.status == CmpTransactionModel.Status.ISSUED
        and not record.implicit_confirm
        and record.confirmed_at is None
        and record.confirmation_deadline is not None
        and record.confirmation_deadline <= now
    )


def require_awaiting_confirmation(record: CmpTransactionModel) -> None:
    """Reject confirmations after completion or expiry, including scheduler delays."""
    if (
        record.status != CmpTransactionModel.Status.ISSUED
        or record.implicit_confirm
        or record.confirmed_at is not None
        or confirmation_is_due(record, timezone.now())
    ):
        msg = 'CMP transaction is no longer awaiting certificate confirmation.'
        raise ValueError(msg)


def expire_confirmation(transaction_pk: int, *, now: datetime | None = None) -> bool:
    """Atomically reject an expired transaction and apply its persisted policy once."""
    with locked_confirmation(transaction_pk) as (record, config):
        current_time = now or timezone.now()
        if not confirmation_is_due(record, current_time):
            return False
        if record.confirmation_timeout_policy == 'revoke':
            if record.final_certificate is None:
                msg = 'Cannot reject an issued CMP transaction without its certificate.'
                raise ValueError(msg)
            ca = record.domain.issuing_ca if record.domain else None
            revoke_certificate(record.final_certificate, reason='unspecified', ca=ca)
        elif record.confirmation_timeout_policy != 'log':
            msg = 'Unknown CMP confirmation timeout policy.'
            raise ValueError(msg)

        if record.operation == 'initialization' and config is not None:
            # Failed onboarding must remain pending and require fresh bootstrap
            # material. Do not mark it successfully onboarded on a timeout.
            invalidate_onboarding_secrets(config)

        record.status = CmpTransactionModel.Status.REJECTED
        record.detail = f'Certificate confirmation timed out (policy: {record.confirmation_timeout_policy}).'
        record.finalized_at = current_time
        record.save(update_fields=['status', 'detail', 'finalized_at', 'updated_at'])
        transaction.on_commit(lambda: logger.warning('CMP transaction %s: %s', record.transaction_id, record.detail))
        return True


def expire_due_confirmations() -> int:
    """Sweep expired confirmations; failed rejections remain eligible for retry."""
    now = timezone.now()
    transaction_pks = CmpTransactionModel.objects.filter(
        status=CmpTransactionModel.Status.ISSUED,
        implicit_confirm=False,
        confirmed_at__isnull=True,
        confirmation_deadline__lte=now,
    ).values_list('pk', flat=True)
    expired = 0
    for transaction_pk in transaction_pks.iterator():
        try:
            expired += expire_confirmation(transaction_pk, now=now)
        except Exception:
            logger.exception('Failed to expire CMP confirmation for transaction %s', transaction_pk)
    return expired
