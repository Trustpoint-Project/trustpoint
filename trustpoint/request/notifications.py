# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Create notifications for final PKI request failures."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from django.db import transaction

from devices.models import DeviceModel
from management.models import NotificationConfig, NotificationModel, NotificationStatus
from pki.models import DomainModel

if TYPE_CHECKING:
    from request.request_context import BaseRequestContext

logger = logging.getLogger(__name__)

_PROTOCOLS = frozenset({'cmp', 'est', 'rest', 'scep', 'manual'})
_OPERATIONS = frozenset({
    'simpleenroll', 'simplereenroll', 'enroll', 'reenroll', 'initialization',
    'certification', 'revocation', 'certconf', 'pkcsreq', 'renewalreq',
})


def notify_request_failure(context: BaseRequestContext) -> None:
    """Record one warning per failed request when notifications are enabled.

    Only allowlisted protocol/operation names and resolved model references are
    retained. Error messages, response bodies and request credentials are omitted.
    Notification storage failures must not replace the original protocol response.
    """
    if context.failure_notification_sent:
        return
    try:
        # A savepoint also protects callers that are already inside a transaction.
        with transaction.atomic():
            if not NotificationConfig.objects.filter(enabled=True).exists():
                return
            device = context.device if isinstance(context.device, DeviceModel) and context.device.pk else None
            domain = context.domain if isinstance(context.domain, DomainModel) and context.domain.pk else None
            notification = NotificationModel.objects.create(
                event='REQUEST_FAILED',
                notification_source=(
                    NotificationModel.NotificationSource.DEVICE
                    if device else NotificationModel.NotificationSource.SYSTEM
                ),
                notification_type=NotificationModel.NotificationTypes.WARNING,
                message_type=NotificationModel.NotificationMessageType.REQUEST_FAILED,
                device=device,
                domain=domain,
                message_data={
                    'protocol': context.protocol if context.protocol in _PROTOCOLS else 'unknown',
                    'operation': context.operation if context.operation in _OPERATIONS else 'unknown',
                },
            )
            new_status, _ = NotificationStatus.objects.get_or_create(status=NotificationStatus.StatusChoices.NEW)
            notification.statuses.add(new_status)
        context.failure_notification_sent = True
    except Exception:
        logger.exception('Unable to create PKI request failure notification.')
