"""Management command for Trustpoint backup manifest sidecars."""

from __future__ import annotations

from typing import Any

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError, CommandParser

from management.backup_artifacts import (
    BackupManifestError,
    verify_backup_manifest,
    write_backup_manifest,
)


class Command(BaseCommand):
    """Write or verify a Trustpoint backup manifest sidecar."""

    help = 'Write or verify the manifest sidecar for a Trustpoint database backup.'

    def add_arguments(self, parser: CommandParser) -> None:
        """Add command arguments."""
        parser.add_argument('--filename', type=str, required=True, help='Backup filename in BACKUP_FILE_PATH.')
        parser.add_argument('--verify', action='store_true', help='Verify the existing manifest instead of writing it.')

    def handle(self, *_args: Any, **options: Any) -> None:
        """Write or verify a backup manifest sidecar."""
        backup_path = settings.BACKUP_FILE_PATH / str(options['filename'])
        try:
            if options.get('verify'):
                manifest = verify_backup_manifest(backup_path)
                self.stdout.write(
                    self.style.SUCCESS(
                        f'Backup manifest verified: {backup_path.name} '
                        f'({manifest.trustpoint_version}, {manifest.database_engine})'
                    )
                )
                return

            manifest_path = write_backup_manifest(backup_path)
        except (BackupManifestError, FileNotFoundError) as exc:
            raise CommandError(str(exc)) from exc

        self.stdout.write(self.style.SUCCESS(f'Backup manifest written: {manifest_path.name}'))
