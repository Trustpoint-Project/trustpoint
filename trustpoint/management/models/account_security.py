# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Global account security policy."""

from __future__ import annotations

from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import models
from django.utils.translation import gettext_lazy as _

MIN_IDLE_TIMEOUT_MINUTES = 15
MAX_IDLE_TIMEOUT_MINUTES = 30 * 24 * 60


class AccountSecurityConfig(models.Model):
    """Singleton containing runtime account security policy."""

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
        for field in ('api_credential_expiry_days', 'failed_login_attempts'):
            value = getattr(self, field)
            if value is not None and value < 1:
                raise ValidationError({field: _('This value must be positive.')})
        if not MIN_IDLE_TIMEOUT_MINUTES <= self.idle_timeout_minutes <= MAX_IDLE_TIMEOUT_MINUTES:
            raise ValidationError({'idle_timeout_minutes': _('Idle timeout must be between 15 minutes and 30 days.')})

    @classmethod
    def get(cls) -> AccountSecurityConfig:
        """Return the singleton, creating it with behavior-preserving defaults."""
        if getattr(settings, 'TRUSTPOINT_IS_BOOTSTRAP', False):
            return cls(pk=1)
        config, _ = cls.objects.get_or_create(pk=1)
        return config
