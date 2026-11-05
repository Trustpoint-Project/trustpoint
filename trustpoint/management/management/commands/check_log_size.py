# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Check the combined size of application logs and their rotated backups."""

from __future__ import annotations

import math
import re
import stat
from pathlib import Path
from typing import Any

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError

from management.models import NotificationModel, NotificationStatus


class Command(BaseCommand):
    """Warn when retained application log data exceeds the configured threshold."""

    help = 'Check the combined size of trustpoint.log and its rotated backups.'

    def add_arguments(self, parser: Any) -> None:
        """Add an optional threshold override in MiB."""
        parser.add_argument(
            '--max-size-mib',
            type=float,
            default=settings.LOG_SIZE_WARNING_THRESHOLD_MIB,
            help='Warning threshold in MiB (default: LOG_SIZE_WARNING_THRESHOLD_MIB, 10 MiB).',
        )

    def handle(self, *args: Any, **options: Any) -> None:  # noqa: ARG002
        """Measure file sizes without reading log contents and create a warning."""
        threshold_mib = options['max_size_mib']
        if not math.isfinite(threshold_mib) or threshold_mib <= 0:
            msg = '--max-size-mib must be a finite positive number.'
            raise CommandError(msg)

        log_dir = Path(settings.LOG_DIR_PATH)
        try:
            total_bytes = self._get_log_size(log_dir)
        except FileNotFoundError:
            self.stdout.write(self.style.WARNING(f'Log directory does not exist: {log_dir}'))
            return
        except OSError as exc:
            msg = f'Unable to measure log data in {log_dir}: {exc}'
            raise CommandError(msg) from exc

        total_mib = total_bytes / (1024 * 1024)
        if total_bytes <= threshold_mib * 1024 * 1024:
            self.stdout.write(self.style.SUCCESS(f'Log data size: {total_mib:.2f} MiB (within threshold).'))
            return

        notification, created = NotificationModel.objects.update_or_create(
            event='LOG_SIZE_EXCEEDED',
            defaults={
                'notification_source': NotificationModel.NotificationSource.SYSTEM,
                'notification_type': NotificationModel.NotificationTypes.WARNING,
                'message_type': NotificationModel.NotificationMessageType.LOG_SIZE_EXCEEDED,
                'message_data': {
                    'size_mib': f'{total_mib:.2f}',
                    'threshold_mib': threshold_mib,
                },
            },
        )
        if created:
            new_status, _ = NotificationStatus.objects.get_or_create(status=NotificationStatus.StatusChoices.NEW)
            notification.statuses.add(new_status)
        self.stdout.write(
            self.style.WARNING(f'Log data size: {total_mib:.2f} MiB exceeds {threshold_mib:g} MiB.')
        )

    @staticmethod
    def _get_log_size(log_dir: Path) -> int:
        """Sum regular log files, tolerating files removed during rotation."""
        total_bytes = 0
        for path in log_dir.iterdir():
            if not re.fullmatch(r'trustpoint\.log(?:\.\d+)?', path.name):
                continue
            try:
                file_stat = path.lstat()
            except FileNotFoundError:
                continue
            if stat.S_ISREG(file_stat.st_mode):
                total_bytes += file_stat.st_size
        return total_bytes
