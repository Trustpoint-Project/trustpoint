"""Operational startup manager for Trustpoint."""

from __future__ import annotations

import os
import sys
from pathlib import Path

from django.conf import settings as django_settings
from django.core.management import CommandError, call_command
from django.core.management.base import BaseCommand
from packaging.version import InvalidVersion, Version

from management.models import AppVersion
from management.util.output_wrapper import CommandOutputWrapper
from management.util.startup_context import StartupContextBuilder
from management.util.startup_strategies import CompletedRuntimeStartupStrategy
from management.util.startup_strategies import StartupStrategySelector
from setup_wizard.models import SetupWizardCompletedModel


class Command(BaseCommand):
    """Prepare Trustpoint operational runtime state after migrations are safe."""

    help = 'Prepare Trustpoint operational runtime and TLS state.'

    def handle(self, **_options: dict[str, str]) -> None:
        """Entrypoint for the command."""
        self._check_env_file_exists()
        self.manage_startup()
        self._check_auto_setup()

    def _check_env_file_exists(self) -> None:
        """Check if .env file exists, fail startup if it does not."""
        env_file = Path('/var/www/html/trustpoint/.env')
        if not env_file.exists():
            self.stdout.write(
                self.style.ERROR(
                    'FATAL: No .env file found. Trustpoint requires a .env file to start.\n'
                    'Please create /var/www/html/trustpoint/.env with the required configuration.\n'
                    'See .env.example for reference.'
                )
            )
            sys.exit(1)

    def _check_auto_setup(self) -> None:
        """Check if auto-setup should be performed from environment variables."""
        auto_setup = os.getenv('TP_AUTO_SETUP', '').strip().lower() in {'1', 'true', 'yes', 'on'}

        if not auto_setup:
            return

        if SetupWizardCompletedModel.setup_wizard_completed():
            self.stdout.write(self.style.WARNING('TP_AUTO_SETUP is enabled but setup already completed, skipping'))
            return

        self.stdout.write(self.style.WARNING('TP_AUTO_SETUP is enabled, running auto-setup from environment...'))
        try:
            call_command('auto_setup_from_env')
        except CommandError as e:
            self.stdout.write(self.style.ERROR(f'Auto-setup failed: {e}'))
            raise

    def manage_startup(self) -> None:
        """Ensure the operational DB schema is ready, then initialize runtime state."""
        if getattr(django_settings, 'TRUSTPOINT_IS_BOOTSTRAP', False):
            msg = 'startup_manager is operational-only. Use bootstrap_manager with TRUSTPOINT_PHASE=bootstrap.'
            raise CommandError(msg)

        self.stdout.write('=== Starting Trustpoint Startup Sequence ===')
        output = CommandOutputWrapper(self.stdout, self.style)

        current_version = self._parse_version(django_settings.APP_VERSION)
        output.write(f'Current app version: {current_version}')

        output.write('Running database migrations...')
        call_command('migrate')

        app_version = AppVersion.objects.first()
        if app_version is None:
            output.write('App version from DB: None')
            db_version = None
        else:
            output.write(f'App version from DB: {app_version.version}')
            db_version = self._parse_version(app_version.version)

        context = (
            StartupContextBuilder(output, current_version)
            .with_db_version(db_version)
            .collect_backend_state()
            .collect_appsecret_state()
            .collect_tls_staging_state()
            .build()
        )

        strategy = CompletedRuntimeStartupStrategy()
        output.write('Selected operational startup path.')
        output.write(f'Strategy description: {strategy.get_description()}')

        try:
            strategy.execute(context)
        except RuntimeError as exc:
            error_msg = str(exc)
            output.write(output.error(error_msg))
            raise CommandError(error_msg) from exc

        output.write(output.success('=== Startup Sequence Completed Successfully ==='))

    @staticmethod
    def _parse_version(version_str: str) -> Version:
        """Parse and validate an application version string."""
        try:
            return Version(version_str)
        except InvalidVersion as exc:
            msg = f'Invalid version format: {version_str}'
            raise CommandError(msg) from exc
