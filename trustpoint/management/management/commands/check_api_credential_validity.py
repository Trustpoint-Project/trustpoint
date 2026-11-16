# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Check active API credentials against their explicit and policy expiry dates."""

from datetime import timedelta
from typing import Any

from django.core.management.base import BaseCommand
from django.utils import timezone

from management.models import AccountSecurityConfig, NotificationConfig, NotificationModel
from management.notifications import notify_operational_issue, resolve_operational_issue
from users.models import ServiceAccountCredential


class Command(BaseCommand):
    """Warn before API credentials expire, using the certificate warning period."""

    help = 'Check service account API credentials for approaching or elapsed expiration.'

    def handle(self, *args: Any, **options: Any) -> None:  # noqa: ARG002
        """Evaluate active credentials without retaining their secrets or client IDs."""
        config = NotificationConfig.get()
        if not config.enabled:
            return
        maximum_age = AccountSecurityConfig.get().api_credential_expiry_days
        now = timezone.now()
        threshold = now + timedelta(days=config.cert_expiry_warning_days)
        active_events = []
        for credential in ServiceAccountCredential.objects.filter(
            is_active=True,
            service_account__is_active=True,
        ).select_related('service_account'):
            expiry = credential.effective_expiry(maximum_age)
            event = f'API_CREDENTIAL_{credential.pk}'
            if expiry is None or expiry > threshold:
                continue
            active_events.append(event)
            expired = expiry <= now
            notify_operational_issue(
                event,
                (
                    NotificationModel.NotificationMessageType.API_CREDENTIAL_EXPIRED
                    if expired
                    else NotificationModel.NotificationMessageType.API_CREDENTIAL_EXPIRING
                ),
                (
                    NotificationModel.NotificationTypes.CRITICAL
                    if expired
                    else NotificationModel.NotificationTypes.WARNING
                ),
                {
                    'username': credential.service_account.username,
                    'credential_id': credential.pk,
                    'expires_at': expiry.strftime('%Y-%m-%d %H:%M:%S'),
                },
                strict=True,
            )
        for event in (
            NotificationModel.objects.filter(event__startswith='API_CREDENTIAL_')
            .exclude(
                event__in=active_events,
            )
            .values_list('event', flat=True)
        ):
            resolve_operational_issue(event, strict=True)
        self.stdout.write(self.style.SUCCESS('API credential validity check completed.'))
