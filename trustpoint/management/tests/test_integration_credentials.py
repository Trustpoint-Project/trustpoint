# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Verify integration secrets at rest, across recovery, and at form/API boundaries."""

from pathlib import Path
from unittest.mock import patch

import pytest
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission
from django.core.exceptions import ValidationError
from django.db import connection
from django.urls import reverse

from appsecrets.service import CIPHERTEXT_PREFIX, clear_app_secret_cache
from management.forms import BackupOptionsForm, SmtpEmailConfigForm
from management.models import BackupOptions, SmtpEmailConfig
from management.serializer.backup import BackupSerializer


def raw_credentials():
    with connection.cursor() as cursor:
        cursor.execute('SELECT password, private_key, key_passphrase FROM management_backupoptions')
        backup = cursor.fetchone()
        cursor.execute('SELECT password FROM management_smtpemailconfig')
        smtp = cursor.fetchone()
    return (*backup, *smtp)


def backup_data(**overrides):
    return {
        'enable_sftp_storage': True,
        'host': 'backup.example.com',
        'port': 22,
        'user': 'backup',
        'auth_method': BackupOptions.AuthMethod.PASSWORD,
        'remote_directory': '/backups/',
        **overrides,
    }


def smtp_data(**overrides):
    return {
        'enabled': True,
        'host': 'smtp.example.com',
        'port': 587,
        'use_tls': True,
        'username': 'mailer',
        'timeout_seconds': 10,
        'default_from_email': 'mailer@example.com',
        **overrides,
    }


def test_credentials_are_encrypted_and_recovered_only_with_original_kek(monkeypatch, tmp_path):
    secrets = ('  backup-秘密  ', 'synthetic SSH key\n' * 200, 'key-passphrase', '  smtp-秘密  ')
    BackupOptions.objects.create(password=secrets[0], private_key=secrets[1], key_passphrase=secrets[2])
    SmtpEmailConfig.objects.create(password=secrets[3])
    ciphertexts = raw_credentials()
    assert all(value.startswith(CIPHERTEXT_PREFIX) for value in ciphertexts)
    assert all(plaintext not in ciphertext for plaintext, ciphertext in zip(secrets, ciphertexts, strict=True))
    assert BackupOptions.objects.get().private_key == secrets[1]

    from os import environ

    original = environ['TRUSTPOINT_SOFTWARE_KEK_FILE']
    wrong = tmp_path / 'wrong-kek'
    wrong.write_text('cd' * 32)
    monkeypatch.setenv('TRUSTPOINT_SOFTWARE_KEK_FILE', str(wrong))
    clear_app_secret_cache()
    with pytest.raises(ValidationError, match='Failed to decrypt'):
        BackupOptions.objects.get()
    with pytest.raises(ValidationError, match='Failed to decrypt'):
        SmtpEmailConfig.objects.get()
    assert raw_credentials() == ciphertexts

    monkeypatch.setenv('TRUSTPOINT_SOFTWARE_KEK_FILE', original)
    clear_app_secret_cache()
    backup = BackupOptions.objects.get()
    smtp = SmtpEmailConfig.objects.get()
    assert (backup.password, backup.private_key, backup.key_passphrase, smtp.password) == secrets
    assert Path(original).is_file()


def test_empty_secrets_stay_empty_without_loading_crypto():
    with patch(
        'util.encrypted_fields.encrypt_app_secret', side_effect=AssertionError('No key needed for empty values')
    ):
        BackupOptions.objects.create()
        SmtpEmailConfig.objects.create()
    assert raw_credentials() == ('', '', '', '')


def test_maximum_length_unicode_passwords_roundtrip_without_ciphertext_truncation():
    BackupOptions.objects.create(password='密' * 128, key_passphrase='🔑' * 128)
    SmtpEmailConfig.objects.create(password='密' * 1024)
    assert BackupOptions.objects.get().password == '密' * 128
    assert BackupOptions.objects.get().key_passphrase == '🔑' * 128
    assert SmtpEmailConfig.objects.get().password == '密' * 1024
    assert len(raw_credentials()[0]) > 128


@pytest.mark.parametrize('bound', [False, True])
def test_saved_and_submitted_secrets_never_render(bound):
    backup = BackupOptions.objects.create(
        password='stored-backup', private_key='stored-private-key', key_passphrase='stored-passphrase'
    )
    smtp = SmtpEmailConfig.objects.create(password='stored-smtp')
    backup_form = BackupOptionsForm(
        data=backup_data(
            password='submitted-backup', private_key='submitted-private-key', key_passphrase='submitted-passphrase'
        )
        if bound
        else None,
        instance=backup,
    )
    smtp_form = SmtpEmailConfigForm(
        data=smtp_data(password='submitted-smtp', host='') if bound else None, instance=smtp
    )
    if bound:
        assert not backup_form.is_valid()
        assert not smtp_form.is_valid()
    html = backup_form.as_p() + smtp_form.as_p()
    for secret in (
        'stored-backup',
        'stored-private-key',
        'stored-passphrase',
        'stored-smtp',
        'submitted-backup',
        'submitted-private-key',
        'submitted-passphrase',
        'submitted-smtp',
    ):
        assert secret not in html
    assert 'clear_password' in html and 'clear_private_key' in html


def test_blank_smtp_password_keeps_stored_value_and_test_email_uses_it():
    smtp = SmtpEmailConfig.objects.create(password=' stored SMTP password ')
    form = SmtpEmailConfigForm(data=smtp_data(password=''), instance=smtp)
    assert form.is_valid(), form.errors
    configured = form.save(commit=False)
    with patch('django.core.mail.backends.smtp.EmailBackend.send_messages', autospec=True, return_value=1) as send:
        configured.send_test_email('recipient@example.com')
    assert send.call_args.args[0].password == ' stored SMTP password '
    assert SmtpEmailConfig.objects.get().password == ' stored SMTP password '
    form.save()
    assert SmtpEmailConfig.objects.get().password == ' stored SMTP password '


def test_smtp_password_can_be_replaced_and_explicitly_cleared():
    smtp = SmtpEmailConfig.objects.create(password='old')
    form = SmtpEmailConfigForm(data=smtp_data(password='  replacement  '), instance=smtp)
    assert form.is_valid(), form.errors
    form.save()
    assert SmtpEmailConfig.objects.get().password == '  replacement  '
    form = SmtpEmailConfigForm(data=smtp_data(password='', clear_password=True), instance=SmtpEmailConfig.objects.get())
    assert form.is_valid(), form.errors
    form.save()
    assert SmtpEmailConfig.objects.get().password == ''


def test_backup_blank_credentials_are_preserved_and_can_be_replaced():
    backup = BackupOptions.objects.create(**backup_data(password=' saved password '))
    form = BackupOptionsForm(data=backup_data(password='', host='new.example.com'), instance=backup)
    assert form.is_valid(), form.errors
    form.save()
    assert BackupOptions.objects.get().password == ' saved password '
    form = BackupOptionsForm(data=backup_data(password='new password'), instance=BackupOptions.objects.get())
    assert form.is_valid(), form.errors
    form.save()
    assert BackupOptions.objects.get().password == 'new password'


def test_blank_ssh_key_and_passphrase_are_preserved_but_clearing_passphrase_is_explicit():
    data = backup_data(auth_method=BackupOptions.AuthMethod.SSH_KEY)
    backup = BackupOptions.objects.create(
        **data, private_key='saved key\nwith newlines', key_passphrase='saved passphrase'
    )
    form = BackupOptionsForm(data=data, instance=backup)
    assert form.is_valid(), form.errors
    form.save()
    assert BackupOptions.objects.get().private_key == 'saved key\nwith newlines'
    assert BackupOptions.objects.get().key_passphrase == 'saved passphrase'
    form = BackupOptionsForm(data={**data, 'clear_key_passphrase': True}, instance=BackupOptions.objects.get())
    assert form.is_valid(), form.errors
    form.save()
    assert BackupOptions.objects.get().key_passphrase == ''


def test_switching_backup_authentication_clears_only_obsolete_saved_credentials():
    backup = BackupOptions.objects.create(**backup_data(password='old password'))
    form = BackupOptionsForm(
        data=backup_data(auth_method=BackupOptions.AuthMethod.SSH_KEY, private_key='new key\n'), instance=backup
    )
    assert form.is_valid(), form.errors
    form.save()
    backup.refresh_from_db()
    assert backup.password == '' and backup.private_key == 'new key\n'
    form = BackupOptionsForm(data=backup_data(password='replacement'), instance=backup)
    assert form.is_valid(), form.errors
    form.save()
    backup.refresh_from_db()
    assert backup.password == 'replacement' and backup.private_key == ''


def test_backup_credentials_can_be_explicitly_cleared_when_storage_is_disabled():
    backup = BackupOptions.objects.create(
        password='saved password', private_key='saved key', key_passphrase='saved pass'
    )
    form = BackupOptionsForm(
        data=backup_data(
            enable_sftp_storage=False, clear_password=True, clear_private_key=True, clear_key_passphrase=True
        ),
        instance=backup,
    )
    assert form.is_valid(), form.errors
    form.save()
    backup.refresh_from_db()
    assert (backup.password, backup.private_key, backup.key_passphrase) == ('', '', '')


def test_active_password_auth_cannot_clear_its_required_password():
    backup = BackupOptions.objects.create(**backup_data(password='saved password'))
    form = BackupOptionsForm(data=backup_data(clear_password=True), instance=backup)
    assert not form.is_valid()
    assert 'password' in form.errors
    assert BackupOptions.objects.get().password == 'saved password'


@pytest.mark.parametrize(
    'form_class,data',
    [
        (BackupOptionsForm, backup_data(password='new-secret-value-943', clear_password=True)),
        (SmtpEmailConfigForm, smtp_data(password='new-secret-value-943', clear_password=True)),
    ],
)
def test_replacement_and_clear_cannot_be_requested_together(form_class, data):
    form = form_class(data=data)
    assert not form.is_valid()
    assert 'password' in form.errors
    assert 'new-secret-value-943' not in form.as_p()


def test_backup_get_requires_permission_and_never_discloses_secrets(client):
    backup = BackupOptions.objects.create(
        password='saved-backup-secret', private_key='saved-ssh-key', key_passphrase='saved-key-passphrase'
    )
    user = get_user_model().objects.create_user(username='backup-reader', password='synthetic-password')
    client.force_login(user)
    url = reverse('management:backups')
    assert client.get(url).status_code == 403
    permission = Permission.objects.get(codename='manage_backups', content_type__app_label='users')
    user.role.permissions.add(permission)
    response = client.get(url)
    assert response.status_code == 200
    for secret in ('saved-backup-secret', 'saved-ssh-key', 'saved-key-passphrase'):
        assert secret.encode() not in response.content
    assert set(BackupSerializer(backup).data) == {'id', 'remote_directory'}


def test_smtp_settings_page_does_not_render_saved_password(client):
    SmtpEmailConfig.objects.create(password='stored-smtp-secret-938')
    user = get_user_model().objects.create_user(username='settings-reader', password='synthetic-password')
    client.force_login(user)
    response = client.get(reverse('management:settings'))
    assert response.status_code == 200
    assert b'stored-smtp-secret-938' not in response.content
    assert b'clear_password' in response.content
