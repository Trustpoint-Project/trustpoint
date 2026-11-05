# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Check whether a completed local backup exists within the configured interval."""

from __future__ import annotations

import math
import stat
from datetime import datetime
from pathlib import Path
from typing import Any

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError
from django.utils import timezone

from management.backup_artifacts import MANIFEST_SUFFIX, BackupManifestError, load_backup_manifest
from management.models import NotificationModel, NotificationStatus
from setup_wizard.operational_attach import SUPPORTED_BACKUP_MANIFEST_VERSION


class Command(BaseCommand):
    """Warn when no recent completed local backup is available."""

    help = 'Check whether a completed local backup exists within the last configured number of days.'

    def add_arguments(self, parser: Any) -> None:
        """Add an optional maximum backup age in days."""
        parser.add_argument(
            '--max-age-days',
            type=float,
            default=settings.BACKUP_MAX_AGE_DAYS,
            help='Maximum backup age in days (default: BACKUP_MAX_AGE_DAYS, 7 days).',
        )

    def handle(self, *args: Any, **options: Any) -> None:  # noqa: ARG002
        """Find the latest completion timestamp and update the overdue warning."""
        max_age_days = options['max_age_days']
        if not math.isfinite(max_age_days) or max_age_days <= 0:
            msg = '--max-age-days must be a finite positive number.'
            raise CommandError(msg)

        now = timezone.now()
        backup_dir = Path(settings.BACKUP_FILE_PATH)
        try:
            latest_backup = self._latest_backup(backup_dir, now)
        except FileNotFoundError:
            latest_backup = None
        except OSError as exc:
            msg = f'Unable to inspect backups in {backup_dir}: {exc}'
            raise CommandError(msg) from exc

        if latest_backup is not None and (now - latest_backup).total_seconds() / 86400 <= max_age_days:
            self.stdout.write(self.style.SUCCESS(f'Latest completed local backup: {latest_backup.isoformat()}.'))
            return

        notification, created = NotificationModel.objects.update_or_create(
            event='BACKUP_OVERDUE',
            defaults={
                'notification_source': NotificationModel.NotificationSource.SYSTEM,
                'notification_type': NotificationModel.NotificationTypes.WARNING,
                'message_type': NotificationModel.NotificationMessageType.BACKUP_OVERDUE,
                'message_data': {
                    'max_age_days': max_age_days,
                    'last_backup': latest_backup.isoformat() if latest_backup else None,
                },
            },
        )
        if created:
            new_status, _ = NotificationStatus.objects.get_or_create(status=NotificationStatus.StatusChoices.NEW)
            notification.statuses.add(new_status)
        self.stdout.write(self.style.WARNING(f'No completed local backup found within the last {max_age_days:g} days.'))

    @staticmethod
    def _latest_backup(backup_dir: Path, now: datetime) -> datetime | None:
        """Read completion metadata for nonempty regular payloads with supported manifests.

        Manifests are written after dbbackup succeeds. This checks availability
        and age; payload integrity verification remains a separate operation.
        """
        latest = None
        for manifest_path in backup_dir.iterdir():
            if not manifest_path.name.endswith(MANIFEST_SUFFIX) or manifest_path.name == MANIFEST_SUFFIX:
                continue
            backup_path = manifest_path.with_name(manifest_path.name.removesuffix(MANIFEST_SUFFIX))
            try:
                payload_stat = backup_path.lstat()
                if (
                    not stat.S_ISREG(manifest_path.lstat().st_mode)
                    or not stat.S_ISREG(payload_stat.st_mode)
                    or payload_stat.st_size == 0
                ):
                    continue
                manifest = load_backup_manifest(backup_path)
            except (BackupManifestError, FileNotFoundError):
                continue
            if (
                manifest.manifest_version != SUPPORTED_BACKUP_MANIFEST_VERSION
                or not manifest.payload_sha256
                or not manifest.created_at
            ):
                continue
            try:
                completed_at = datetime.fromisoformat(manifest.created_at)
            except ValueError:
                continue
            if timezone.is_naive(completed_at) or completed_at > now:
                continue
            if latest is None or completed_at > latest:
                latest = completed_at
        return latest
