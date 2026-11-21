# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Logging Configuration Model."""

from __future__ import annotations

import logging

from django.db import models
from django.utils.translation import gettext_lazy as _


def apply_persisted_log_level() -> None:
    """Apply the stored log level to this process at startup."""
    config = LoggingConfig.objects.only('log_level').first()
    if config is None:
        return
    names = LoggingConfig.LogLevelChoices.names
    if config.log_level in names:
        level_name = config.log_level
    else:
        try:
            level_name = LoggingConfig.LogLevelChoices(config.log_level).name
        except ValueError:
            return
    logging.getLogger().setLevel(getattr(logging, level_name))


class LoggingConfig(models.Model):
    """Logging Configuration model."""

    class LogLevelChoices(models.TextChoices):
        """Types of log levels."""

        DEBUG = '0', _('Debug')
        INFO = '1', _('Info')
        WARNING = '2', _('Warning')
        ERROR = '3', _('Error')
        CRITICAL = '4', _('Critical')

    log_level = models.CharField(max_length=8, choices=LogLevelChoices, default=LogLevelChoices.INFO)
    crypto_backend_audit_enabled = models.BooleanField(
        verbose_name=_('Audit crypto backend operations'),
        default=False,
        help_text=_(
            'Record sanitized crypto backend operations in the audit log. '
            'Secrets, PINs, key material, payload bytes, and signatures are never stored.'
        ),
    )
    last_updated = models.DateTimeField(auto_now=True)

    def __str__(self) -> str:
        """Output as string."""
        return f'{self.log_level}'
