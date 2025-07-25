"""Management command to check and update the Trustpoint database version."""

from typing import TYPE_CHECKING, Any

from django.conf import settings as django_settings
from django.core.management import CommandError, call_command
from django.core.management.base import BaseCommand, CommandParser
from django.db.utils import OperationalError, ProgrammingError
from packaging.version import InvalidVersion, Version

from settings.models import AppVersion


class Command(BaseCommand):
    """A Django management command to check and update the Trustpoint version."""

    help = 'Updates app version'

    def add_arguments(self, parser: CommandParser) -> None:
        """Adds command arguments/options."""
        parser.add_argument('--filename', type=str, required=True, help='Backup filename (e.g. dump.sql.gz)')

    def handle(self, *_args: tuple[str], **options: Any) -> None:
        """Executes the command."""
        filename: str = options.get('filename', '')
        if not filename:
            self.stdout.write('ERROR: No filename provided.')
            raise ValueError
        self.backup_trustpoint(filename)

    def backup_trustpoint(self, filename: str) -> None:
        """Checks current state of trustpoint and acts accordingly."""
        call_command('dbbackup', '-o', filename + '.dump.gz', '-z')
