# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Verify SMTP configuration uses mailers for saved and unsaved settings."""

# ruff: noqa: PLR2004, S105, S106, SLF001

from unittest.mock import patch

from django.conf import settings
from django.core.mail import mailers
from django.test import SimpleTestCase, override_settings

from management.models.email import SmtpEmailConfig


@override_settings(MAILERS={
    'default': {'BACKEND': SmtpEmailConfig.CONSOLE_BACKEND},
    'other': {'BACKEND': 'django.core.mail.backends.locmem.EmailBackend'},
})
class SmtpEmailConfigTests(SimpleTestCase):
    """Exercise runtime mailers without a database or SMTP server."""

    def test_apply_preserves_other_mailers_and_disabling_restores_console(self) -> None:
        """Only the default mailer changes when SMTP is enabled or disabled."""
        config = SmtpEmailConfig(enabled=True, host='smtp.example.com', username='mailer', password='secret')
        other = settings.MAILERS['other']
        config.apply_to_django_settings()

        connection = mailers.default
        assert connection.host == 'smtp.example.com'
        assert connection.port == 587
        assert connection.use_tls
        assert connection.username == 'mailer'
        assert connection.password == 'secret'
        assert connection.timeout == 10
        assert settings.MAILERS['other'] == other

        config.enabled = False
        config.apply_to_django_settings()
        assert settings.MAILERS['default'] == {'BACKEND': SmtpEmailConfig.CONSOLE_BACKEND}

    @override_settings(MAILERS={'default': {
        'BACKEND': SmtpEmailConfig.SMTP_BACKEND,
        'OPTIONS': {'host': 'smtp.example.com', 'use_ssl': True, 'username': 'mailer', 'password': 'secret'},
    }})
    def test_initial_settings_follow_mailer_security_defaults(self) -> None:
        """Seeding the model uses mailer options, including implicit SSL's port."""
        config = SmtpEmailConfig(**SmtpEmailConfig._initial_from_django_settings())
        assert config.enabled
        assert config.host == 'smtp.example.com'
        assert config.port == 465
        assert config.use_ssl
        assert not config.use_tls
        assert config.username == 'mailer'
        assert config.password == 'secret'

    def test_unsaved_test_email_does_not_change_active_mailers(self) -> None:
        """SMTP tests deliver with form values while leaving global settings intact."""
        active_mailers = settings.MAILERS
        config = SmtpEmailConfig(enabled=True, host='unsaved.example.com', default_from_email='sender@example.com')
        with patch('django.core.mail.backends.smtp.EmailBackend.send_messages', autospec=True, return_value=1) as send:
            assert config.send_test_email('recipient@example.com') == 1

        connection, messages = send.call_args.args
        assert connection.host == 'unsaved.example.com'
        assert messages[0].from_email == 'sender@example.com'
        assert messages[0].to == ['recipient@example.com']
        assert settings.MAILERS is active_mailers
