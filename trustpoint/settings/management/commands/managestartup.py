
from django.conf import settings as django_settings
from django.core.management import call_command
from django.core.management.base import BaseCommand
from django.core.management import CommandError
from django.db.utils import OperationalError, ProgrammingError
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

            if not app_version:
                call_command('inittrustpoint')
            elif app_version.version == current:
                # Consider always running migrations
                call_command('inittrustpoint', '--nomigrations')
                call_command('trustpointrestore')
            # TODO: Careful here, 1.12 < 1.2 in string comparison, need specific semver comparison
            elif app_version.version > current:
                error_msg = (
                    f'Current app version {current} is lower than the version {app_version.version} in the DB. '
                    'This is not supported. '
                    'Please update the app or remove the postgres volume to restore another backup.')
                raise CommandError(error_msg)
            elif app_version.version < current:
                self.stdout.write(f'Updating app version from {app_version.version} to {current}')
                call_command('inittrustpoint')
                call_command('trustpointrestore')
                app_version.version = current
                app_version.save()
                self.stdout.write(f'Trustpoint version updated to {current}')
            else:
                pass

        except (ProgrammingError, OperationalError):
            call_command('inittrustpoint')
