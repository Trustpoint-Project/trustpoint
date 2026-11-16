# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Check availability of the configured cryptographic backend."""

from typing import Any

from django.core.management.base import BaseCommand
from django.db import transaction

from crypto.application.capabilities import get_active_backend_capability_report
from crypto.domain.errors import AuthenticationError, CryptoError
from crypto.models import CryptoProviderProfileModel
from management.models import NotificationConfig, NotificationModel, NotificationStatus
from management.notifications import notify_operational_issue, resolve_operational_issue


class Command(BaseCommand):
    """Probe the backend live rather than reporting a stale capability snapshot."""

    help = 'Check the configured cryptographic backend for availability.'

    @transaction.atomic
    def handle(self, *args: Any, **options: Any) -> None:  # noqa: ARG002
        """Create a critical alert for a failed probe, and resolve it on recovery."""
        if not NotificationConfig.get().enabled:
            return
        event = 'CRYPTO_BACKEND_UNAVAILABLE'
        # Serialize probes so concurrent checks cannot each retry a rejected PIN.
        profile = CryptoProviderProfileModel.objects.filter(active=True).select_for_update().first()
        if profile is None:
            resolve_operational_issue(event, strict=True)
            return
        if (
            NotificationModel.objects.filter(
                event=event,
                message_data__profile_id=profile.pk,
                message_data__authentication_failed=True,
            )
            .exclude(statuses__status=NotificationStatus.StatusChoices.SOLVED)
            .exists()
        ):
            self.stdout.write(
                self.style.WARNING('Token authentication retries paused; review and solve the alert to retry.')
            )
            return
        authentication_failed = False
        try:
            report = get_active_backend_capability_report(refresh=True, strict=True, authenticate=True)
            available = report.available
        except CryptoError as exc:
            available = False
            authentication_failed = isinstance(exc, AuthenticationError)
        if available:
            resolve_operational_issue(event, strict=True)
        else:
            notify_operational_issue(
                event,
                NotificationModel.NotificationMessageType.CRYPTO_BACKEND_UNAVAILABLE,
                NotificationModel.NotificationTypes.CRITICAL,
                {'backend': profile.name, 'profile_id': profile.pk, 'authentication_failed': authentication_failed},
                strict=True,
            )
        self.stdout.write(self.style.SUCCESS('Cryptographic backend check completed.'))
