# Copyright (c) 2025 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Management command to create a new local backup."""

from pathlib import Path
from typing import Any

from django.conf import settings
from django.core.files import locks
from django.core.management import call_command
from django.core.management.base import BaseCommand, CommandError, CommandParser

from management.backup_artifacts import write_backup_manifest


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
            msg = 'No filename provided.'
            raise CommandError(msg)
        self.backup_trustpoint(filename)

    def backup_trustpoint(self, filename: str) -> None:
        """Checks current state of trustpoint and acts accordingly."""
        if Path(filename).name != filename:
            msg = 'Backup filename must not include path separators.'
            raise CommandError(msg)
        backup_path = settings.BACKUP_FILE_PATH / filename
        backup_path.parent.mkdir(parents=True, exist_ok=True)
        # Keep this file in place so every process locks the same inode.
        with (backup_path.parent / '.backup.lock').open('a') as backup_lock:
            if not locks.lock(backup_lock, locks.LOCK_EX):
                msg = 'Unable to acquire the backup lock.'
                raise CommandError(msg)
            if backup_path.exists():
                msg = f'Backup file already exists: {filename}'
                raise CommandError(msg)
            call_command('dbbackup', '-o', filename, '-z')
            manifest_path = write_backup_manifest(backup_path)
        self.stdout.write(f'Backup manifest written: {manifest_path.name}')
