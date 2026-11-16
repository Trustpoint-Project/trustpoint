# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Reconcile account lockout notifications, including locks created before checks were enabled."""

from typing import Any

from django.core.management.base import BaseCommand
from django.db import transaction

from management.models import NotificationConfig, NotificationModel
from management.notifications import notify_operational_issue, resolve_operational_issue
from users.models import TrustpointUser


class Command(BaseCommand):
    """Report accounts blocked by repeated failed logins."""

    help = 'Check for accounts locked by failed login protection.'

    def handle(self, *args: Any, **options: Any) -> None:  # noqa: ARG002
        """Keep one alert per locked account and solve it after unblocking."""
        if not NotificationConfig.get().enabled:
            return
        active_events = []
        for user_id in TrustpointUser.objects.filter(blocked_by_failed_logins=True).values_list('pk', flat=True):
            with transaction.atomic():
                user = TrustpointUser.objects.select_for_update().filter(pk=user_id).first()
                if user is None or not user.blocked_by_failed_logins:
                    continue
                event = f'ACCOUNT_LOCKED_{user.pk}'
                active_events.append(event)
                notify_operational_issue(
                    event,
                    NotificationModel.NotificationMessageType.ACCOUNT_LOCKED,
                    NotificationModel.NotificationTypes.WARNING,
                    {'username': user.username},
                    strict=True,
                )
        for event in (
            NotificationModel.objects.filter(event__startswith='ACCOUNT_LOCKED_')
            .exclude(
                event__in=active_events,
            )
            .values_list('event', flat=True)
        ):
            with transaction.atomic():
                user = (
                    TrustpointUser.objects.select_for_update()
                    .filter(
                        pk=event.removeprefix('ACCOUNT_LOCKED_'),
                    )
                    .first()
                )
                if user is None or not user.blocked_by_failed_logins:
                    resolve_operational_issue(event, strict=True)
        self.stdout.write(self.style.SUCCESS('Account lockout check completed.'))
