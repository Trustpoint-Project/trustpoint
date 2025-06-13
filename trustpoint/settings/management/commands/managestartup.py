
from django.conf import settings as django_settings
from django.core.management import call_command
from django.core.management.base import BaseCommand
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
                call_command('inittrustpoint', '--nomigrations')
                call_command('trustpointrestore')
            elif app_version.version >= current:
                call_command('updateversion')
            else:
                pass

        except (ProgrammingError, OperationalError):
            call_command('inittrustpoint')
