"""Management command to create a new local backup."""

from typing import Any

from django.core.management import call_command
from django.core.management.base import BaseCommand, CommandParser


class Command(BaseCommand):
    """A Django management command to create a new local DB backup (.dump.gz)."""

    help = 'Create a new local DB backup'

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
        call_command('dbbackup', '-o', filename, '-z')
