# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Pinned SFTP host keys are validated and managed with backup settings."""

from unittest.mock import patch

import paramiko
import pytest
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission
from django.core.exceptions import ValidationError
from django.db import connection
from django.urls import reverse

from management.forms import BackupOptionsForm
from management.models import BackupOptions
from management.serializer.backup import BackupSerializer
from management.tests.ssh_helpers import SFTP_HOST_KEY
from util.sftp import SftpClient, SftpError

pytestmark = pytest.mark.django_db


@pytest.fixture
def sftp_data():
    return {
        'enable_sftp_storage': True,
        'host': 'backup.example.com',
        'host_key': SFTP_HOST_KEY,
        'port': 2222,
        'user': 'backup',
        'auth_method': BackupOptions.AuthMethod.PASSWORD,
        'password': 'configured-password',
        'remote_directory': '/backups/',
    }


def test_verified_public_key_is_saved_unencrypted_and_used_by_client(sftp_data):
    form = BackupOptionsForm(data=sftp_data)
    assert form.is_valid(), form.errors
    backup = form.save()
    with connection.cursor() as cursor:
        cursor.execute('SELECT host_key FROM management_backupoptions WHERE id = %s', [backup.pk])
        assert cursor.fetchone()[0] == SFTP_HOST_KEY
    assert SftpClient().host_key == SFTP_HOST_KEY
    assert BackupSerializer(backup).data['host_key'] == SFTP_HOST_KEY


@pytest.mark.parametrize(
    'host_key',
    [
        'not a key',
        'ssh-rsa invalid',
        f'{SFTP_HOST_KEY}\n{SFTP_HOST_KEY}',
        '-----BEGIN PRIVATE KEY-----\nprivate data\n-----END PRIVATE KEY-----',
    ],
)
def test_invalid_keys_are_rejected_by_model_form_and_api(sftp_data, host_key):
    with pytest.raises(ValidationError) as error:
        BackupOptions(host_key=host_key).full_clean()
    assert 'host_key' in error.value.message_dict
    form = BackupOptionsForm(data={**sftp_data, 'host_key': host_key})
    assert not form.is_valid()
    assert 'host_key' in form.errors
    serializer = BackupSerializer(data={'host_key': host_key})
    assert not serializer.is_valid()
    assert 'host_key' in serializer.errors


def test_enabling_sftp_requires_public_key(sftp_data):
    form = BackupOptionsForm(data={**sftp_data, 'host_key': ''})
    assert not form.is_valid()
    assert 'host_key' in form.errors


def test_legacy_settings_without_pin_are_preserved_but_cannot_connect(sftp_data):
    backup = BackupOptions.objects.create(**{**sftp_data, 'host_key': ''})
    with patch('util.sftp.paramiko.SSHClient') as ssh:
        with pytest.raises(SftpError, match='host public key is required'):
            SftpClient().test_connection()
    ssh.assert_not_called()
    backup.refresh_from_db()
    assert backup.password == 'configured-password'


def test_connection_uses_unsaved_host_key_without_replacing_saved_pin(client, sftp_data):
    backup = BackupOptions.objects.create(**sftp_data)
    user = get_user_model().objects.create_user(username='backup-admin', password='test-password')
    user.role.permissions.add(Permission.objects.get(codename='manage_backups', content_type__app_label='users'))
    client.force_login(user)
    key = paramiko.RSAKey.generate(2048)
    replacement = f'{key.get_name()} {key.get_base64()}'
    with patch('management.views.backup.SftpClient') as sftp:
        response = client.post(
            reverse('management:backups'),
            {
                **sftp_data,
                'test_sftp_connection': '',
                'host_key': replacement,
            },
        )
    assert response.status_code == 200
    assert sftp.call_args.kwargs['overrides']['host_key'] == replacement
    sftp.return_value.test_connection.assert_called_once()
    backup.refresh_from_db()
    assert backup.host_key == SFTP_HOST_KEY


def test_public_key_with_comment_is_accepted(sftp_data):
    form = BackupOptionsForm(data={**sftp_data, 'host_key': f'{SFTP_HOST_KEY} backup-server'})
    assert form.is_valid(), form.errors
