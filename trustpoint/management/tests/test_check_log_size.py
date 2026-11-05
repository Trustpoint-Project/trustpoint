# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Tests for the application log size notification command."""

from io import StringIO
from pathlib import Path
from unittest.mock import patch

import pytest
from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import override_settings

from management.management.commands.check_log_size import Command
from management.models import NotificationModel, NotificationStatus


@pytest.mark.django_db
def test_combined_logs_create_and_update_warning(tmp_path):
    """Count backups, render the warning, and preserve acknowledgement on repeat runs."""
    (tmp_path / 'trustpoint.log').write_bytes(b'a' * 600)
    (tmp_path / 'trustpoint.log.1').write_bytes(b'b' * 600)
    with override_settings(LOG_DIR_PATH=tmp_path):
        call_command('check_log_size', max_size_mib=1 / 1024, stdout=StringIO())

        notification = NotificationModel.objects.get(event='LOG_SIZE_EXCEEDED')
        assert notification.notification_type == NotificationModel.NotificationTypes.WARNING
        assert notification.notification_source == NotificationModel.NotificationSource.SYSTEM
        assert notification.statuses.filter(status='NEW').exists()
        assert 'Application log data' in notification.short_translated
        assert '0.00 MiB' in notification.long_translated

        acknowledged, _ = NotificationStatus.objects.get_or_create(status='ACK')
        notification.statuses.set([acknowledged])
        (tmp_path / 'trustpoint.log').write_bytes(b'a' * 1024 * 1024)
        call_command('check_log_size', max_size_mib=1 / 1024, stdout=StringIO())

    notification.refresh_from_db()
    assert NotificationModel.objects.filter(event='LOG_SIZE_EXCEEDED').count() == 1
    assert notification.message_data['size_mib'] == '1.00'
    assert list(notification.statuses.values_list('status', flat=True)) == ['ACK']


@pytest.mark.parametrize('size', [0, 1023, 1024])
def test_no_warning_at_or_below_threshold(tmp_path, size):
    (tmp_path / 'trustpoint.log').write_bytes(b'a' * size)
    output = StringIO()
    with override_settings(LOG_DIR_PATH=tmp_path, LOG_SIZE_WARNING_THRESHOLD_MIB=1 / 1024):
        call_command('check_log_size', stdout=output)
    assert 'within threshold' in output.getvalue()


def test_only_regular_application_log_files_are_counted(tmp_path):
    (tmp_path / 'trustpoint.log').write_bytes(b'a' * 10)
    (tmp_path / 'trustpoint.log.12').write_bytes(b'b' * 20)
    (tmp_path / 'other.log').write_bytes(b'c' * 100)
    (tmp_path / 'trustpoint.log.backup').write_bytes(b'd' * 100)
    (tmp_path / 'trustpoint.log.1').mkdir()
    (tmp_path / 'trustpoint.log.2').symlink_to(tmp_path / 'other.log')
    assert Command._get_log_size(tmp_path) == 30


def test_disappearing_rotated_file_is_ignored(tmp_path):
    (tmp_path / 'trustpoint.log.1').touch()
    with patch.object(Path, 'lstat', side_effect=FileNotFoundError):
        assert Command._get_log_size(tmp_path) == 0


def test_missing_directory_is_reported(tmp_path):
    output = StringIO()
    with override_settings(LOG_DIR_PATH=tmp_path / 'missing'):
        call_command('check_log_size', stdout=output)
    assert 'Log directory does not exist' in output.getvalue()


def test_filesystem_error_fails_the_command(tmp_path):
    with (
        override_settings(LOG_DIR_PATH=tmp_path),
        patch.object(Path, 'iterdir', side_effect=PermissionError('denied')),
        pytest.raises(CommandError, match='Unable to measure log data'),
    ):
        call_command('check_log_size', stdout=StringIO())


@pytest.mark.parametrize('threshold', [0, -1, float('nan'), float('inf')])
def test_invalid_threshold_is_rejected(threshold):
    with pytest.raises(CommandError, match='finite positive number'):
        call_command('check_log_size', max_size_mib=threshold, stdout=StringIO())
