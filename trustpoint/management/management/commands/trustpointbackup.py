# Copyright (c) 2025 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Management command to create a new local backup."""

from contextlib import ExitStack
from pathlib import Path
from typing import Any

from django.conf import settings
from django.core.files import locks
from django.core.management import call_command
from django.core.management.base import BaseCommand, CommandError, CommandParser

from management.backup_artifacts import write_backup_manifest
from management.models import NotificationModel
from management.notifications import notify_operational_issue, resolve_operational_issue


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
        # Hold the shared file lock until the matching alert update has finished.
        with ExitStack() as resources:
            try:
                backup_path.parent.mkdir(parents=True, exist_ok=True)
                # Keep this file in place so every process locks the same inode.
                backup_lock = resources.enter_context((backup_path.parent / '.backup.lock').open('a'))
                if not locks.lock(backup_lock, locks.LOCK_EX):
                    msg = 'Unable to acquire the backup lock.'
                    raise CommandError(msg)  # noqa: TRY301
                if backup_path.exists():
                    msg = f'Backup file already exists: {filename}'
                    raise CommandError(msg)  # noqa: TRY301
                call_command('dbbackup', '-o', filename, '-z')
                manifest_path = write_backup_manifest(backup_path)
            except Exception:
                notify_operational_issue(
                    'BACKUP_FAILED',
                    NotificationModel.NotificationMessageType.BACKUP_FAILED,
                    NotificationModel.NotificationTypes.CRITICAL,
                    {'stage': 'local backup creation'},
                )
                raise
            resolve_operational_issue('BACKUP_FAILED')
        self.stdout.write(f'Backup manifest written: {manifest_path.name}')
