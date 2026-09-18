# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Interactive authentication with runtime failed-login protection."""

from typing import Any

from django.contrib import messages
from django.contrib.auth.backends import ModelBackend
from django.db.models import F
from django.utils.translation import gettext

from management.models import AccountSecurityConfig

from .models import TrustpointUser


class TrustpointModelBackend(ModelBackend):
    """Authenticate human users and maintain consecutive failure state."""

    def authenticate(
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
        if user.account_type == TrustpointUser.AccountType.SERVICE or user.blocked_by_failed_logins:
            return None
        if user.check_password(password) and self.user_can_authenticate(user):
            if user.failed_login_attempts:
                TrustpointUser.objects.filter(pk=user.pk).update(failed_login_attempts=0)
            return user
        config = AccountSecurityConfig.get()
        if config.failed_login_attempts and user.is_active:
            TrustpointUser.objects.filter(pk=user.pk).update(failed_login_attempts=F('failed_login_attempts') + 1)
            user.refresh_from_db(fields=['failed_login_attempts', 'is_active'])
            if user.failed_login_attempts >= config.failed_login_attempts:
                user.is_active = False
                user.blocked_by_failed_logins = True
                user.save(update_fields=['is_active', 'blocked_by_failed_logins'])
                if request is not None:
                    messages.error(
                        request,
                        gettext(
                            'This account has been blocked after too many failed login attempts. '
                            'Contact an administrator to restore access.',
                        ),
                    )
        return None
