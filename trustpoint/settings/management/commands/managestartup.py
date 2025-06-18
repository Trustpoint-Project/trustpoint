"""Management command to check and update the Trustpoint database version."""

from django.conf import settings as django_settings
from django.core.management import CommandError, call_command
from django.core.management.base import BaseCommand
from django.db.utils import OperationalError, ProgrammingError
from packaging.version import InvalidVersion, Version

from settings.models import AppVersion


class Command(BaseCommand):
    """A Django management command to check and update the Trustpoint version."""

    help = 'Updates app version'

    def handle(self, **_options: dict[str, str]) -> None:
        """Entrypoint for the command."""
        self.manage_startup()

    def manage_startup(self) -> None:
        """Checks current state of trustpoint and acts accordingly."""
        try:
            app_version = AppVersion.objects.first()
            current = django_settings.APP_VERSION
        except (ProgrammingError, OperationalError):
            # If the AppVersion table does not exist, we assume the DB is not initialized
            db_error_msg: str = 'AppVersion table not found. DB probably not initialized'
            self.stdout.write(self.style.ERROR(db_error_msg))
            call_command('inittrustpoint')
            return

        if not app_version:
            db_error_msg: str = 'DB AppVersion not found. DB probably not initialized'
            self.stdout.write(self.style.ERROR(db_error_msg))
            call_command('inittrustpoint')
            return

        db_version, current_version = self._parse_versions(app_version.version, current)

        if db_version == current_version:
            call_command('inittrustpoint')
            call_command('trustpointrestore')
        elif current_version < db_version:
            error_msg = (
                f'Current app version {current} is lower than the version {db_version} in the DB. '
                'This is not supported. '
                'Please update the Trustpoint container or remove the postgres volume to restore another backup.')
            raise CommandError(error_msg)
        else: # Current Trustpoint container version is newer than DB version, update the app version
            self.stdout.write(f'Updating app version from {db_version} to {current}')
            call_command('inittrustpoint')
            call_command('trustpointrestore')
            app_version.version = current
            app_version.save()
            self.stdout.write(f'Trustpoint version updated to {current}')

    def _parse_versions(self, db_version_str: str, current_version_str: str) -> tuple[Version, Version]:
        """Parse the version strings into Version objects."""
        try:
            db_version = Version(db_version_str)
        except InvalidVersion as e:
            exc_msg = f'Invalid version format {db_version_str} in the database AppVersion.'
            raise CommandError(exc_msg) from e

        try:
            current_version = Version(current_version_str)
        except InvalidVersion as e:
            exc_msg = f'Current Trustpoint version format {current_version_str} is invalid.'
            raise CommandError(exc_msg) from e

        return db_version, current_version
