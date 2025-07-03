"""Management command to initialize the Trustpoint on container startup."""

from django.conf import settings as django_settings
from django.core.management import call_command
from django.core.management.base import BaseCommand, CommandParser
from django.utils.translation import gettext as _

from settings.models import AppVersion


class Command(BaseCommand):
    """A Django management command to initialize the Trustpoint.

    Called by the 'managestartup' command
    """

    help = 'Initializes the Trustpoint on container startup.'

    def add_arguments(self, parser: CommandParser) -> None:
        """Adds command arguments/options."""
        parser.add_argument('--nomigrations', action='store_true', help='Migrations will not be executed.')

    def handle(self, **options: dict[str, str]) -> None:
        """Entrypoint for the command."""
        self.init_trustpoint(**options)

    def init_trustpoint(self, **options: dict[str, str]) -> None:
        """Run migrations (if enabled) and preparatory Django management cmds."""
        self.stdout.write('Start initializing the trustpoint...')
        current = django_settings.APP_VERSION
        if not options.get('nomigrations'):
            setup_msg: str = _('Starting setup script...')
            self.stdout.write(self.style.NOTICE(_(setup_msg)))

            self.stdout.write('Running migrate...')
            call_command('migrate')

            ver, _created = AppVersion.objects.get_or_create(pk=1)
            ver.version = current
            ver.save()
        self.stdout.write('Collecting static files...')
        call_command('collectstatic', '--noinput')
        self.stdout.write('Compiling Messages...')
        call_command('compilemessages', '-l', 'de', '-l', 'en')
        self.stdout.write(f'Initialization of version {current} successful.')
