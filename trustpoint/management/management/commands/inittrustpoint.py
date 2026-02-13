"""Management command to initialize the Trustpoint on container startup."""

import io
from pathlib import Path

from django.conf import settings as django_settings
from django.core.management import call_command
from django.contrib.auth.models import User
from django.core.management.base import BaseCommand, CommandParser
from django.utils.translation import gettext as _

from management.models import AppVersion


class Command(BaseCommand):
    """A Django management command to initialize the Trustpoint.

    Called by the 'managestartup' command
    """

    help = 'Initializes the Trustpoint on container startup.'

    def add_arguments(self, parser: CommandParser) -> None:
        """Adds command arguments/options."""
        parser.add_argument('--nomigrations', action='store_true', help='Migrations will not be executed.')
        parser.add_argument('--tls', action='store_true', help='Tls is getting prepared.')
        parser.add_argument('--admin', action='store_true', help='Create super user.')

    def handle(self, **options: dict[str, str]) -> None:
        """Entrypoint for the command."""
        self.init_trustpoint(**options)

    def init_trustpoint(self, **options: dict[str, str]) -> None:
        """Run migrations (if enabled) and preparatory Django management cmds."""
        self.stdout.write('Start initializing the trustpoint...')
        current = django_settings.APP_VERSION

        try:
            with Path('/etc/hostname').open('r') as f:
                container_id = f.read().strip()
        except FileNotFoundError:
            container_id = 'unknown'
        if not options.get('nomigrations'):
            setup_msg: str = _('Starting setup script...')
            self.stdout.write(_(setup_msg))

            self.stdout.write('Running migrate...')
            call_command('migrate')

            ver, _created = AppVersion.objects.get_or_create(pk=1)
            ver.version = current
            ver.container_id = container_id
            ver.save()
        with io.StringIO() as fake_out:
            self.stdout.write('Collecting static files...')
            call_command('collectstatic', '--noinput', stdout=fake_out)
            self.stdout.write('Done')
            self.stdout.write('Compiling Messages...')
            call_command('compilemessages', '-l', 'de', '-l', 'en', stdout=fake_out)
            self.stdout.write('Done')

        if options.get('tls'):
            self.stdout.write('Preparing TLS certificate...')
            from management.models import KeyStorageConfig

            crypto_config, created = KeyStorageConfig.objects.get_or_create(
                pk=1,
                defaults={
                    'storage_type': KeyStorageConfig.StorageType.SOFTWARE,
                },
            )
            if created:
                self.stdout.write('Created software crypto storage configuration')
            else:
                self.stdout.write('Using existing crypto storage configuration')
            call_command('tls_cred', '--write_out')
            self.stdout.write('Done')

        if options.get('admin'):
            self.stdout.write('Creating superuser...')
            call_command('createsuperuser', interactive=False, username='admin', email='')
            user = User.objects.get(username='admin')
            user.set_password('testing321')
            user.save()
            self.stdout.write('Superuser created:')
            self.stdout.write('  Username: admin')
            self.stdout.write('  Password: testing321')
