# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Interactive authentication with runtime failed-login protection."""

from datetime import timedelta
from typing import Any

from django.contrib import messages
from django.contrib.auth.backends import ModelBackend
from django.db import transaction
from django.db.models import F
from django.utils import timezone
from django.utils.translation import gettext

from management.models import AccountSecurityConfig, NotificationModel
from management.notifications import notify_operational_issue

from .models import TrustpointUser

INTERACTIVE_BACKEND = 'users.management_backend.TrustpointModelBackend'
# Temporary so one anonymous attacker cannot lock an account out permanently.
LOCKOUT_MINUTES = 15


class TrustpointModelBackend(ModelBackend):
    """Authenticate human users and maintain consecutive failure state."""

    def authenticate(  # noqa: C901, PLR0911 - lockout, expiry and failure counting share one path
        self,
        request: Any,
        username: str | None = None,
        password: str | None = None,
        **kwargs: Any,
    ) -> TrustpointUser | None:
        """Authenticate a human user and update consecutive failure state."""
        username = username or kwargs.get(TrustpointUser.USERNAME_FIELD)
        if not username or password is None:
            return None
        try:
            user = TrustpointUser.objects.get(username=username)
        except TrustpointUser.DoesNotExist:
            return None
        if user.account_type == TrustpointUser.AccountType.SERVICE:
            # Return the user so the web login can show its specific message.
            # Service accounts never use the failed-login lockout path.
            if user.check_password(password) and self.user_can_authenticate(user):
                return user
            return None
        if user.blocked_by_failed_logins:
            return None
        now = timezone.now()
        if user.failed_login_locked_until is not None:
            if user.failed_login_locked_until > now:
                return None
            # The temporary lock expired; give the account a clean slate.
            user.failed_login_attempts = 0
            user.failed_login_locked_until = None
            TrustpointUser.objects.filter(pk=user.pk).update(
                failed_login_attempts=0,
                failed_login_locked_until=None,
            )
        if user.check_password(password) and self.user_can_authenticate(user):
            if user.failed_login_attempts:
                TrustpointUser.objects.filter(pk=user.pk).update(failed_login_attempts=0)
            return user
        config = AccountSecurityConfig.get()
        if config.failed_login_attempts and user.is_active:
            with transaction.atomic():
                TrustpointUser.objects.filter(pk=user.pk).update(failed_login_attempts=F('failed_login_attempts') + 1)
                user.refresh_from_db(fields=['failed_login_attempts', 'is_active'])
                if user.failed_login_attempts >= config.failed_login_attempts:
                    user.failed_login_locked_until = now + timedelta(minutes=LOCKOUT_MINUTES)
                    user.failed_login_attempts = 0
                    user.save(update_fields=['failed_login_attempts', 'failed_login_locked_until'])
                    notify_operational_issue(
                        f'ACCOUNT_LOCKED_{user.pk}',
                        NotificationModel.NotificationMessageType.ACCOUNT_LOCKED,
                        NotificationModel.NotificationTypes.WARNING,
                        {'username': user.username},
                    )
                    if request is not None:
                        messages.error(
                            request,
                            gettext(
                                'This account is temporarily locked after too many failed login attempts. '
                                'Try again in %(minutes)s minutes or contact an administrator.',
                            )
                            % {'minutes': LOCKOUT_MINUTES},
                        )
        return None
