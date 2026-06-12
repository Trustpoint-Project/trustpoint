"""Email backend configuration models."""

from __future__ import annotations

from contextlib import suppress
from typing import Any, ClassVar

from django.conf import settings
from django.core.mail import EmailMessage, get_connection
from django.db import models
from django.utils import timezone
from django.utils.translation import gettext_lazy as _


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
    password = models.CharField(max_length=1024, blank=True)
    timeout_seconds = models.PositiveIntegerField(default=10)
    default_from_email = models.EmailField(default='no-reply@trustpoint.de')
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
    def _settings_bool(cls, name: str, *, default: bool = False) -> bool:
        return bool(getattr(settings, name, default))

    @classmethod
    def _settings_int(cls, name: str, default: int) -> int:
        raw_value = getattr(settings, name, default)
        try:
            return int(raw_value)
        except (TypeError, ValueError):
            return default

    @classmethod
    def _initial_from_django_settings(cls) -> dict[str, Any]:
        backend = getattr(settings, 'EMAIL_BACKEND', '')
        return {
            'enabled': backend == cls.SMTP_BACKEND and bool(getattr(settings, 'EMAIL_HOST', '')),
            'host': getattr(settings, 'EMAIL_HOST', ''),
            'port': cls._settings_int('EMAIL_PORT', 587),
            'use_tls': cls._settings_bool('EMAIL_USE_TLS', default=True),
            'use_ssl': cls._settings_bool('EMAIL_USE_SSL', default=False),
            'username': getattr(settings, 'EMAIL_HOST_USER', ''),
            'password': getattr(settings, 'EMAIL_HOST_PASSWORD', ''),
            'timeout_seconds': cls._settings_int('EMAIL_TIMEOUT', 10),
            'default_from_email': getattr(settings, 'DEFAULT_FROM_EMAIL', 'no-reply@trustpoint.de'),
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

    def apply_to_django_settings(self) -> None:
        """Apply this persisted configuration to Django's runtime mail settings."""
        settings.DEFAULT_FROM_EMAIL = self.default_from_email
        settings.EMAIL_TIMEOUT = self.timeout_seconds

        if self.enabled:
            settings.EMAIL_BACKEND = self.SMTP_BACKEND
            settings.EMAIL_HOST = self.host
            settings.EMAIL_PORT = self.port
            settings.EMAIL_USE_TLS = self.use_tls
            settings.EMAIL_USE_SSL = self.use_ssl
            settings.EMAIL_HOST_USER = self.username
            settings.EMAIL_HOST_PASSWORD = self.password
            return

        settings.EMAIL_BACKEND = self.CONSOLE_BACKEND
        settings.EMAIL_HOST = ''
        settings.EMAIL_PORT = self.port
        settings.EMAIL_USE_TLS = False
        settings.EMAIL_USE_SSL = False
        settings.EMAIL_HOST_USER = ''
        settings.EMAIL_HOST_PASSWORD = ''

    def send_test_email(self, recipient: str) -> int:
        """Send a small test email through this SMTP configuration."""
        connection = get_connection(
            backend=self.SMTP_BACKEND if self.enabled else self.CONSOLE_BACKEND,
            host=self.host,
            port=self.port,
            username=self.username or None,
            password=self.password or None,
            use_tls=self.use_tls,
            use_ssl=self.use_ssl,
            timeout=self.timeout_seconds,
        )
        message = EmailMessage(
            subject=_('Trustpoint SMTP test email'),
            body=_(
                'This is a test email from Trustpoint.\n\n'
                'If you received this message, Trustpoint can talk to the configured SMTP server.\n\n'
                'Sent at: %(timestamp)s'
            ) % {'timestamp': timezone.now().isoformat()},
            from_email=self.default_from_email,
            to=[recipient],
            connection=connection,
        )
        return int(message.send(fail_silently=False))


def apply_saved_smtp_email_config() -> None:
    """Apply the saved SMTP config if the table and singleton row are available."""
    with suppress(Exception):
        smtp_config = SmtpEmailConfig.get_existing()
        if smtp_config is not None:
            smtp_config.apply_to_django_settings()
