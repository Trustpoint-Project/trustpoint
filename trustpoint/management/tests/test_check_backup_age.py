# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Tests for local backup age notifications."""

import json
from datetime import UTC, datetime, timedelta
from io import StringIO
from pathlib import Path
from unittest.mock import patch

import pytest
from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import override_settings

from management.backup_artifacts import backup_manifest_path
from management.management.commands.check_backup_age import Command
from management.models import NotificationModel, NotificationStatus
from setup_wizard.operational_attach import SUPPORTED_BACKUP_MANIFEST_VERSION

NOW = datetime(2026, 10, 20, 12, tzinfo=UTC)


def make_backup(directory, name='backup.dump.gz', completed_at=None):
    payload = directory / name
    payload.write_bytes(b'database backup')
    manifest = {
        'manifest_version': SUPPORTED_BACKUP_MANIFEST_VERSION,
        'trustpoint_version': '1.0',
        'crypto_backend_kind': 'software',
        'app_secret_backend_kind': 'software',
        'payload_sha256': 'a' * 64,
        'created_at': (completed_at or NOW).isoformat(),
    }
    backup_manifest_path(payload).write_text(json.dumps(manifest))
    return payload


@pytest.mark.django_db
def test_overdue_backup_warns_and_preserves_status(tmp_path):
    make_backup(tmp_path, completed_at=NOW - timedelta(days=8))
    with (
        override_settings(BACKUP_FILE_PATH=tmp_path),
        patch('management.management.commands.check_backup_age.timezone.now', return_value=NOW),
    ):
        call_command('check_backup_age', stdout=StringIO())
        notification = NotificationModel.objects.get(event='BACKUP_OVERDUE')
        assert notification.notification_type == NotificationModel.NotificationTypes.WARNING
        assert notification.notification_source == NotificationModel.NotificationSource.SYSTEM
        assert notification.statuses.filter(status='NEW').exists()
        assert notification.short_translated == 'No recent local backup'
        assert '7 days' in notification.long_translated

        acknowledged, _ = NotificationStatus.objects.get_or_create(status='ACK')
        notification.statuses.set([acknowledged])
        call_command('check_backup_age', max_age_days=3, stdout=StringIO())

    notification.refresh_from_db()
    assert NotificationModel.objects.filter(event='BACKUP_OVERDUE').count() == 1
    assert notification.message_data['max_age_days'] == 3
    assert notification.message_data['last_backup'] == (NOW - timedelta(days=8)).isoformat()
    assert list(notification.statuses.values_list('status', flat=True)) == ['ACK']


@pytest.mark.django_db
@pytest.mark.parametrize('missing_directory', [False, True])
def test_no_backups_warns(tmp_path, missing_directory):
    directory = tmp_path / 'missing' if missing_directory else tmp_path
    with override_settings(BACKUP_FILE_PATH=directory):
        call_command('check_backup_age', stdout=StringIO())
    assert NotificationModel.objects.get(event='BACKUP_OVERDUE').message_data['last_backup'] is None


@pytest.mark.parametrize('age', [timedelta(days=1), timedelta(days=7)])
def test_recent_backup_and_exact_boundary_do_not_warn(tmp_path, age):
    make_backup(tmp_path, completed_at=NOW - age)
    with (
        override_settings(BACKUP_FILE_PATH=tmp_path),
        patch('management.management.commands.check_backup_age.timezone.now', return_value=NOW),
    ):
        output = StringIO()
        call_command('check_backup_age', stdout=output)
    assert 'Latest completed local backup' in output.getvalue()


def test_newest_completion_time_is_used_instead_of_file_mtime(tmp_path):
    make_backup(tmp_path, name='old.dump.gz', completed_at=NOW - timedelta(days=30))
    make_backup(tmp_path, name='recent.dump.gz', completed_at=NOW - timedelta(days=1))
    assert Command._latest_backup(tmp_path, NOW) == NOW - timedelta(days=1)


@pytest.mark.django_db
def test_setting_default_and_cli_override(tmp_path):
    make_backup(tmp_path, completed_at=NOW - timedelta(days=2))
    with (
        override_settings(BACKUP_FILE_PATH=tmp_path, BACKUP_MAX_AGE_DAYS=1),
        patch('management.management.commands.check_backup_age.timezone.now', return_value=NOW),
    ):
        output = StringIO()
        call_command('check_backup_age', max_age_days=3, stdout=output)
        assert 'Latest completed local backup' in output.getvalue()
        assert not NotificationModel.objects.filter(event='BACKUP_OVERDUE').exists()
        call_command('check_backup_age', stdout=StringIO())
        assert NotificationModel.objects.get(event='BACKUP_OVERDUE').message_data['max_age_days'] == 1


@pytest.mark.parametrize('invalid', ['missing', 'empty', 'symlink', 'malformed', 'future', 'naive', 'unsupported', 'no_date'])
def test_incomplete_or_invalid_backups_are_ignored(tmp_path, invalid):
    payload = make_backup(tmp_path)
    manifest_path = backup_manifest_path(payload)
    if invalid == 'missing':
        payload.unlink()
    elif invalid == 'empty':
        payload.write_bytes(b'')
    elif invalid == 'symlink':
        payload.unlink()
        (tmp_path / 'other').write_bytes(b'data')
        payload.symlink_to(tmp_path / 'other')
    elif invalid == 'malformed':
        manifest_path.write_text('invalid JSON')
    else:
        manifest = json.loads(manifest_path.read_text())
        if invalid == 'future':
            manifest['created_at'] = (NOW + timedelta(days=1)).isoformat()
        elif invalid == 'naive':
            manifest['created_at'] = '2026-10-20T12:00:00'
        elif invalid == 'unsupported':
            manifest['manifest_version'] = SUPPORTED_BACKUP_MANIFEST_VERSION + 1
        elif invalid == 'no_date':
            manifest['created_at'] = None
        manifest_path.write_text(json.dumps(manifest))
    assert Command._latest_backup(tmp_path, NOW) is None


def test_legacy_payload_and_unrelated_files_are_ignored(tmp_path):
    (tmp_path / 'backup.dump.gz').write_bytes(b'legacy backup')
    (tmp_path / 'other.txt').write_text('data')
    (tmp_path / '.manifest.json').write_text('{}')
    assert Command._latest_backup(tmp_path, NOW) is None


def test_filesystem_errors_are_reported(tmp_path):
    with (
        override_settings(BACKUP_FILE_PATH=tmp_path),
        patch.object(Path, 'iterdir', side_effect=PermissionError('denied')),
        pytest.raises(CommandError, match='Unable to inspect backups'),
    ):
        call_command('check_backup_age', stdout=StringIO())


@pytest.mark.parametrize('threshold', [0, -1, float('nan'), float('inf')])
def test_invalid_threshold_is_rejected(threshold):
    with pytest.raises(CommandError, match='finite positive number'):
        call_command('check_backup_age', max_age_days=threshold, stdout=StringIO())
