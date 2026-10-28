# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Email backend configuration models."""

from __future__ import annotations

from contextlib import suppress
from typing import Any, ClassVar

from django.conf import settings
from django.core.mail import EmailMessage
from django.core.mail.handler import MailersHandler
from django.core.validators import MaxLengthValidator
from django.db import models
from django.utils import timezone
from django.utils.translation import gettext_lazy as _

from util.encrypted_fields import EncryptedTextField


class _TestMailers(MailersHandler):
    """Create a mailer for unsaved form values without changing global settings."""

    def __init__(self, config: dict[str, Any]) -> None:
        self._config = config

    @property
    def settings(self) -> dict[str, Any]:
        return {'default': self._config}


class SmtpEmailConfig(models.Model):
    """Persist the global SMTP settings used for workflow and utility email delivery."""

    SINGLETON_ID: ClassVar[int] = 1
    SMTP_BACKEND: ClassVar[str] = 'django.core.mail.backends.smtp.EmailBackend'
    CONSOLE_BACKEND: ClassVar[str] = 'django.core.mail.backends.console.EmailBackend'

    enabled = models.BooleanField(
        default=False,
        help_text=_('Use the configured SMTP server for outbound email.'),
    )
    host = models.CharField(max_length=255, blank=True)
    port = models.PositiveIntegerField(default=587)
    use_tls = models.BooleanField(default=True)
    use_ssl = models.BooleanField(default=False)
    username = models.CharField(max_length=255, blank=True)
    password = EncryptedTextField(max_length=1024, blank=True, validators=[MaxLengthValidator(1024)])
    timeout_seconds = models.PositiveIntegerField(default=10)
    default_from_email = models.EmailField(default='no-reply.trustpoint@localhost')
    last_updated = models.DateTimeField(auto_now=True)

    class Meta:
        """Model metadata."""

        verbose_name = _('SMTP Email Configuration')
        verbose_name_plural = _('SMTP Email Configuration')

    def __str__(self) -> str:
        """Return a concise human-readable representation."""
        if not self.enabled:
            return 'SMTP email disabled'
        return f'SMTP email via {self.host}:{self.port}'

    def save(self, *args: Any, **kwargs: Any) -> None:
        """Persist the singleton config row under the fixed primary key ``1``."""
        self.pk = self.SINGLETON_ID
        super().save(*args, **kwargs)

    @classmethod
    def _initial_from_django_settings(cls) -> dict[str, Any]:
        config = settings.MAILERS.get('default', {})
        options = config.get('OPTIONS', {})
        use_tls = bool(options.get('use_tls', False))
        use_ssl = bool(options.get('use_ssl', False))
        default_port = 465 if use_ssl else (587 if use_tls else 25)
        return {
            'enabled': config.get('BACKEND', cls.SMTP_BACKEND) == cls.SMTP_BACKEND and bool(options.get('host')),
            'host': options.get('host', ''),
            'port': int(options.get('port', default_port)),
            'use_tls': use_tls,
            'use_ssl': use_ssl,
            'username': options.get('username', ''),
            'password': options.get('password', ''),
            'timeout_seconds': int(options.get('timeout') or 10),
            'default_from_email': getattr(settings, 'DEFAULT_FROM_EMAIL', 'no-reply.trustpoint@localhost'),
        }

    @classmethod
    def load(cls) -> SmtpEmailConfig:
        """Load the singleton config row, seeding it from current Django settings on first access."""
        obj, _ = cls.objects.get_or_create(pk=cls.SINGLETON_ID, defaults=cls._initial_from_django_settings())
        return obj

    @classmethod
    def get_existing(cls) -> SmtpEmailConfig | None:
        """Return the saved singleton row without creating one."""
        return cls.objects.filter(pk=cls.SINGLETON_ID).first()

    def _mailer_config(self) -> dict[str, Any]:
        if not self.enabled:
            return {'BACKEND': self.CONSOLE_BACKEND}
        return {
            'BACKEND': self.SMTP_BACKEND,
            'OPTIONS': {
                'host': self.host,
                'port': self.port,
                'username': self.username,
                'password': self.password,
                'use_tls': self.use_tls,
                'use_ssl': self.use_ssl,
                'timeout': self.timeout_seconds,
            },
        }

    def apply_to_django_settings(self) -> None:
        """Apply this persisted configuration to Django's runtime mail settings."""
        settings.DEFAULT_FROM_EMAIL = self.default_from_email
        settings.MAILERS = {**settings.MAILERS, 'default': self._mailer_config()}

    def send_test_email(self, recipient: str) -> int:
        """Send a test email without changing the active mail configuration."""
        connection = _TestMailers(self._mailer_config()).default
        message = EmailMessage(
            subject=_('Trustpoint SMTP test email'),
            body=_(
                'This is a test email from Trustpoint.\n\n'
                'If you received this message, Trustpoint can talk to the configured SMTP server.\n\n'
                'Sent at: %(timestamp)s'
            ) % {'timestamp': timezone.now().isoformat()},
            from_email=self.default_from_email,
            to=[recipient],
        )
        return int(connection.send_messages([message]))


def apply_saved_smtp_email_config() -> None:
    """Apply the saved SMTP config if the table and singleton row are available."""
    with suppress(Exception):
        smtp_config = SmtpEmailConfig.get_existing()
        if smtp_config is not None:
            smtp_config.apply_to_django_settings()
