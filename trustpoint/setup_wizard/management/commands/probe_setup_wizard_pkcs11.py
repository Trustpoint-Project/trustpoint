"""Probe staged setup-wizard PKCS#11 configuration in an isolated process."""

from __future__ import annotations

import json
from typing import Any

from django.core.exceptions import ValidationError as DjangoValidationError
from django.core.management.base import BaseCommand, CommandError, CommandParser

from setup_wizard.models import SetupWizardConfigModel
from setup_wizard.views import probe_staged_pkcs11_config


class Command(BaseCommand):
    """Authenticate and probe the staged PKCS#11 backend."""

    help = 'Probe staged setup-wizard PKCS#11 configuration and print capabilities as JSON.'

    def add_arguments(self, parser: CommandParser) -> None:
        """Add command-line arguments."""
        parser.add_argument('--profile-name', required=True)

    def handle(self, *_args: Any, **options: Any) -> None:
        """Run the staged PKCS#11 probe."""
        profile_name = str(options['profile_name'])
        config_model = SetupWizardConfigModel.get_singleton()
        try:
            capabilities = probe_staged_pkcs11_config(config_model, profile_name=profile_name)
        except DjangoValidationError as exception:
            detail = '; '.join(exception.messages) if hasattr(exception, 'messages') else str(exception)
            raise CommandError(detail) from exception

        self.stdout.write(json.dumps(capabilities.to_json_dict(), sort_keys=True))
