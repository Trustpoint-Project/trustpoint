"""Test staged setup-wizard PKCS#11 support for app-secret protection."""

from __future__ import annotations

from typing import Any

from django.core.exceptions import ValidationError as DjangoValidationError
from django.core.management.base import BaseCommand, CommandError, CommandParser

from setup_wizard.models import SetupWizardConfigModel
from setup_wizard.views import validate_staged_pkcs11_app_secret_protection


class Command(BaseCommand):
    """Run the staged PKCS#11 app-secret protection self-test."""

    help = 'Verify that staged setup-wizard PKCS#11 config can protect Trustpoint application secrets.'

    def add_arguments(self, parser: CommandParser) -> None:
        """Add command-line arguments."""
        parser.add_argument('--profile-name', required=True)

    def handle(self, *_args: Any, **options: Any) -> None:
        """Run the staged PKCS#11 app-secret protection self-test."""
        profile_name = str(options['profile_name'])
        config_model = SetupWizardConfigModel.get_singleton()
        try:
            validate_staged_pkcs11_app_secret_protection(config_model, profile_name=profile_name)
        except DjangoValidationError as exception:
            detail = '; '.join(exception.messages) if hasattr(exception, 'messages') else str(exception)
            raise CommandError(detail) from exception

        self.stdout.write('PKCS#11 app-secret protection self-test completed successfully.')
