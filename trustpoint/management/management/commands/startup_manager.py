"""Startup manager for Trustpoint bootstrap and completed-runtime startup."""

from __future__ import annotations

from django.conf import settings as django_settings
from django.core.management import CommandError, call_command
from django.core.management.base import BaseCommand
from packaging.version import InvalidVersion, Version

from management.models import AppVersion
from management.util.output_wrapper import CommandOutputWrapper
from management.util.startup_context import StartupContextBuilder
from management.util.startup_strategies import StartupStrategySelector


class Command(BaseCommand):
    """Prepare Trustpoint startup state after migrations are safe."""

    help = 'Prepare Trustpoint startup, bootstrap, and TLS runtime state.'

    def handle(self, **_options: dict[str, str]) -> None:
        """Entrypoint for the command."""
        self.manage_startup()

    def manage_startup(self) -> None:
        """Ensure the DB schema is ready, then choose bootstrap or completed-runtime startup."""
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
            .collect_wizard_state()
            .collect_backend_state()
            .collect_appsecret_state()
            .collect_tls_staging_state()
            .build()
        )

        strategy = StartupStrategySelector.select_startup_strategy(context)
        output.write(f'Selected strategy: {strategy.__class__.__name__}')
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
