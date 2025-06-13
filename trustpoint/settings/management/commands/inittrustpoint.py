from typing import Any

from django.conf import settings as django_settings
from django.core.management import call_command
from django.core.management.base import BaseCommand, CommandParser
from django.utils.translation import gettext as _
from settings.models import AppVersion


class Command(BaseCommand):
    """A Django management command to check and update the Trustpoint version."""

    help = 'Updates app version'

    def add_arguments(self, parser: CommandParser) -> None:
        """Adds command arguments/options."""
        parser.add_argument('--nomigrations', action='store_true', help='Migrations will not be executed.')

    def handle(self, **options: dict[str, str]) -> None:
        """Entrypoint for the command."""
        self.init_trustpoint(**options)

    def init_trustpoint(self, **options: dict[str, str]) -> None:
        """Update app version if pyproject.toml is different than version in db."""
        self.stdout.write('Start initializing the trustpoint...')
        current = django_settings.APP_VERSION
        if not options.get('nomigrations'):
            db_error_msg: str = _('Appversion table not found. DB probably not initialized')
            self.stdout.write(self.style.ERROR(db_error_msg))

            setup_msg: str = _('Starting setup script...')
            self.stdout.write(self.style.NOTICE(_(setup_msg)))

            self.stdout.write('Running makemigrations...')
            call_command('makemigrations')
            self.stdout.write('Running migrate...')
            call_command('migrate')

            AppVersion.objects.create(version=current)
        self.stdout.write('Collecting static files...')
        call_command('collectstatic', '--noinput')
        self.stdout.write('Compiling Messages...')
        call_command('compilemessages', '-l', 'de', '-l', 'en')
        self.stdout.write(f'Initialization of version {current} successfully.')
