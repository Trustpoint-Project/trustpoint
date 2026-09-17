# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Global account security policy."""

from __future__ import annotations

from datetime import timedelta

from django.core.exceptions import ValidationError
from django.db import models
from django.utils import timezone
from django.utils.translation import gettext_lazy as _

MIN_IDLE_TIMEOUT_MINUTES = 15
MAX_IDLE_TIMEOUT_MINUTES = 30 * 24 * 60


class AccountSecurityConfig(models.Model):
    """Singleton containing runtime account security policy."""

    password_minimum_length = models.PositiveIntegerField(default=8)
    password_similarity = models.BooleanField(default=True)
    password_common = models.BooleanField(default=True)
    password_numeric = models.BooleanField(default=True)
    password_prevent_reuse = models.BooleanField(default=True)
    password_expiry_days = models.PositiveIntegerField(null=True, blank=True, default=None)
    api_credential_expiry_days = models.PositiveIntegerField(null=True, blank=True, default=None)
    idle_timeout_minutes = models.PositiveIntegerField(default=30)
    failed_login_attempts = models.PositiveIntegerField(null=True, blank=True, default=None)

    class Meta:
        """Configure model metadata."""

        verbose_name = _('account security configuration')
        verbose_name_plural = _('account security configuration')

    def __str__(self) -> str:
        """Return the singleton's display name."""
        return str(self._meta.verbose_name)

    def clean(self) -> None:
        """Validate policy values independently of HTML form constraints."""
        super().clean()
        if self.password_minimum_length < 1:
            raise ValidationError({'password_minimum_length': _('The minimum password length must be positive.')})
        for field in ('password_expiry_days', 'api_credential_expiry_days', 'failed_login_attempts'):
            value = getattr(self, field)
            if value is not None and value < 1:
                raise ValidationError({field: _('This value must be positive.')})
        if not MIN_IDLE_TIMEOUT_MINUTES <= self.idle_timeout_minutes <= MAX_IDLE_TIMEOUT_MINUTES:
            raise ValidationError({'idle_timeout_minutes': _('Idle timeout must be between 15 minutes and 30 days.')})

    @classmethod
    def get(cls) -> AccountSecurityConfig:
        """Return the singleton, creating it with behavior-preserving defaults."""
        config, _ = cls.objects.get_or_create(pk=1)
        return config

    def password_expired(self, changed_at: timezone.datetime | None) -> bool:
        """Return whether a password is expired under the current policy."""
        return bool(
            self.password_expiry_days
            and changed_at
            and timezone.now() >= changed_at + timedelta(days=self.password_expiry_days)
        )
