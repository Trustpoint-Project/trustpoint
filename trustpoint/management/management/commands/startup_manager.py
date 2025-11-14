"""Example integration of startup strategies into managestartup command.

This file shows how to refactor the managestartup.py command to use the strategy pattern.
Copy the relevant parts into managestartup.py to complete the refactoring.
"""

from django.conf import settings as django_settings
from django.core.management import CommandError
from django.core.management.base import BaseCommand
from django.db.utils import OperationalError, ProgrammingError
from packaging.version import InvalidVersion, Version

from management.models import AppVersion
from management.util.output_wrapper import CommandOutputWrapper
from management.util.startup_context import StartupContextBuilder
from management.util.startup_strategies import StartupStrategySelector


class Command(BaseCommand):
    """A Django management command to check and update the Trustpoint version."""

    help = 'Updates app version'

    def handle(self, **_options: dict[str, str]) -> None:
        """Entrypoint for the command."""
        self.manage_startup()

    def manage_startup(self) -> None:
        """Checks current state of trustpoint and acts accordingly."""
        self.stdout.write('=== Starting Trustpoint Startup Sequence ===')

        output = CommandOutputWrapper(self.stdout, self.style)

        current_version_str = django_settings.APP_VERSION
        current_version = self._parse_version(current_version_str)
        output.write(f'Current app version: {current_version}')

        try:
            app_version = AppVersion.objects.first()
            output.write(f'App version from DB: {app_version.version if app_version else "None"}')
        except (ProgrammingError, OperationalError):
            output.write('AppVersion table not found. DB not initialized')

            context = StartupContextBuilder(output, current_version).build_for_db_init()

            strategy = StartupStrategySelector.select_startup_strategy(
                db_initialized=False,
                has_version=False
            )
            strategy.execute(context)
            return

        if not app_version:
            output.write('DB initialized but AppVersion record not found')

            context = StartupContextBuilder(output, current_version).build_for_db_init()

            strategy = StartupStrategySelector.select_startup_strategy(
                db_initialized=True,
                has_version=False
            )
            strategy.execute(context)
            return

        db_version = self._parse_version(app_version.version)

        context = (
            StartupContextBuilder(output, current_version)
            .with_db_version(db_version)
            .collect_wizard_state()
            .collect_storage_config()
            .collect_dek_state()
            .build()
        )

        try:
            strategy = StartupStrategySelector.select_startup_strategy(
                db_initialized=True,
                has_version=True,
                context=context,
                app_version=app_version
            )

            output.write(f'Selected strategy: {strategy.__class__.__name__}')
            output.write(f'Strategy description: {strategy.get_description()}')

            strategy.execute(context)

            output.write(output.success('=== Startup Sequence Completed Successfully ==='))

        except RuntimeError as e:
            error_msg = str(e)
            output.write(output.error(error_msg))
            raise CommandError(error_msg) from e

    def _parse_version(self, version_str: str) -> Version:
        """Parse a version string into a Version object.

        Args:
            version_str: The version string to parse.

        Returns:
            The parsed Version object.

        Raises:
            CommandError: If the version string is invalid.
        """
        try:
            return Version(version_str)
        except InvalidVersion as e:
            exc_msg = f'Invalid version format: {version_str}'
            raise CommandError(exc_msg) from e
