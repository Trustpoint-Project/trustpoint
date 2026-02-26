"""Logging Configuration Model."""

from __future__ import annotations

from django.db import models
from django.utils.translation import gettext_lazy as _


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

    last_updated = models.DateTimeField(auto_now=True)

    def __str__(self) -> str:
        """Output as string."""
        return f'{self.log_level}'
