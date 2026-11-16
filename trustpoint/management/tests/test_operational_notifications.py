# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Operational alert triggers, recovery, and sensitive data boundaries."""

from datetime import timedelta
from io import StringIO
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from django.contrib.auth import authenticate
from django.core.management import CommandError, call_command
from django.utils import timezone

from management.context_processors import notification_alerts
from management.models import AccountSecurityConfig, NotificationConfig, NotificationModel
from management.notifications import check_notification_cycle, notify_operational_issue
from users.models import ServiceAccountCredential, TrustpointUser
from workflows2.models import Workflow2Approval, Workflow2Definition, Workflow2Instance

pytestmark = pytest.mark.django_db


@pytest.fixture(autouse=True)
def config():
    config = NotificationConfig.get()
    config.enabled = True
    config.cert_expiry_warning_days = 7
    config.save()
    return config


@pytest.mark.parametrize(
    ('explicit_days', 'maximum_age', 'age', 'expected'),
    [
        (5, None, 0, 'WAR'),
        (-1, None, 0, 'CRI'),
        (7, None, 0, 'WAR'),
        (8, None, 0, None),
        (None, None, 0, None),
        (None, 30, 25, 'WAR'),
        (None, 30, 30, 'CRI'),
        (90, 30, 31, 'CRI'),
        (2, 30, 0, 'WAR'),
    ],
)
def test_api_credential_expiry(monkeypatch, explicit_days, maximum_age, age, expected):
    now = timezone.now()
    monkeypatch.setattr('django.utils.timezone.now', lambda: now)
    user = TrustpointUser.objects.create_user(username='service', account_type='SERVICE')
    credential = ServiceAccountCredential.objects.create(
        service_account=user,
        client_id='sensitive-client-id',
        hashed_secret='sensitive-secret-hash',
        description='sensitive-description',
        expires_at=now + timedelta(days=explicit_days) if explicit_days is not None else None,
    )
    ServiceAccountCredential.objects.filter(pk=credential.pk).update(created_at=now - timedelta(days=age))
    AccountSecurityConfig.objects.update_or_create(pk=1, defaults={'api_credential_expiry_days': maximum_age})
    for _ in range(2):
        call_command('check_api_credential_validity', stdout=StringIO())
    if expected is None:
        assert not NotificationModel.objects.exists()
    else:
        notification = NotificationModel.objects.get()
        assert notification.notification_type == expected
        assert 'service' in notification.short_translated
        assert str(credential.pk) in notification.long_translated
        assert 'sensitive' not in str(notification.message_data)
    credential.refresh_from_db()
    assert credential.is_expired() == (expected == 'CRI')


def test_api_expiry_escalates_and_resolves(monkeypatch):
    user = TrustpointUser.objects.create_user(username='service', account_type='SERVICE')
    now = timezone.now()
    credential = ServiceAccountCredential.objects.create(
        service_account=user,
        client_id='client',
        hashed_secret='unused',
        expires_at=now + timedelta(days=1),
    )
    call_command('check_api_credential_validity', stdout=StringIO())
    notification = NotificationModel.objects.get()
    notification.statuses.clear()
    monkeypatch.setattr('django.utils.timezone.now', lambda: now + timedelta(days=2))
    call_command('check_api_credential_validity', stdout=StringIO())
    notification.refresh_from_db()
    assert notification.notification_type == 'CRI'
    assert notification.statuses.filter(status='NEW').exists()
    credential.is_active = False
    credential.save()
    call_command('check_api_credential_validity', stdout=StringIO())
    assert notification.statuses.filter(status='SOLV').exists()
    assert not notification.statuses.filter(status='NEW').exists()


def test_account_lock_is_immediate_and_recovers():
    user = TrustpointUser.objects.create_user(username='locked-user', password='valid-password')
    AccountSecurityConfig.objects.update_or_create(pk=1, defaults={'failed_login_attempts': 1})
    assert authenticate(username=user.username, password='wrong-password') is None
    notification = NotificationModel.objects.get(event=f'ACCOUNT_LOCKED_{user.pk}')
    assert notification.message_type == 'ACCOUNT_LOCKED'
    assert 'wrong-password' not in str(notification.message_data)
    call_command('check_account_lockouts', stdout=StringIO())
    assert NotificationModel.objects.count() == 1
    TrustpointUser.objects.filter(pk=user.pk).update(blocked_by_failed_logins=False, is_active=True)
    call_command('check_account_lockouts', stdout=StringIO())
    assert notification.statuses.filter(status='SOLV').exists()
    assert authenticate(username=user.username, password='wrong-password') is None
    assert not notification.statuses.filter(status='SOLV').exists()
    assert notification.statuses.filter(status='NEW').exists()


@pytest.fixture
def crypto_probe(monkeypatch):
    module = 'management.management.commands.check_crypto_backend'
    profile = SimpleNamespace(pk=123, name='HSM')
    profiles = Mock()
    profiles.select_for_update.return_value = profiles
    profiles.first.return_value = profile
    monkeypatch.setattr(f'{module}.CryptoProviderProfileModel.objects.filter', Mock(return_value=profiles))
    probe = Mock(return_value=Mock(available=False, profile_name='HSM', diagnostics=('sensitive error',)))
    monkeypatch.setattr(f'{module}.get_active_backend_capability_report', probe)
    return probe


def test_crypto_backend_probe_failure_and_recovery(crypto_probe):
    probe = crypto_probe
    for _ in range(2):
        call_command('check_crypto_backend', stdout=StringIO())
    probe.assert_called_with(refresh=True, strict=True, authenticate=True)
    notification = NotificationModel.objects.get(event='CRYPTO_BACKEND_UNAVAILABLE')
    assert notification.notification_type == 'CRI'
    assert 'sensitive error' not in str(notification.message_data)
    probe.return_value.available = True
    call_command('check_crypto_backend', stdout=StringIO())
    assert notification.statuses.filter(status='SOLV').exists()
    probe.return_value.available = False
    call_command('check_crypto_backend', stdout=StringIO())
    assert not notification.statuses.filter(status='SOLV').exists()
    assert notification.statuses.filter(status='NEW').exists()


@pytest.fixture
def workflow():
    definition = Workflow2Definition.objects.create(name='Issue certificate', yaml_text='', ir_json={}, ir_hash='test')
    return Workflow2Instance.objects.create(
        definition=definition, event_json={'secret': 'sensitive'}, status='awaiting'
    )


@pytest.mark.parametrize('status', ['error', 'timed_out'])
def test_failed_workflow(workflow, status):
    workflow.status = status
    workflow.status_message = 'sensitive failure details'
    workflow.save()
    for _ in range(2):
        call_command('check_workflow_failures', stdout=StringIO())
    notification = NotificationModel.objects.get()
    assert notification.message_type == 'WORKFLOW_FAILED'
    assert str(workflow.pk) in notification.long_translated
    assert 'sensitive' not in str(notification.message_data)


@pytest.mark.parametrize(
    ('status', 'days', 'expected'),
    [
        ('pending', -1, True),
        ('expired', -1, True),
        ('pending', 1, False),
        ('approved', -1, False),
        ('rejected', -1, False),
        ('pending', None, False),
    ],
)
def test_approval_deadlines(workflow, status, days, expected):
    approval = Workflow2Approval.objects.create(
        instance=workflow,
        step_id='approve',
        status=status,
        expires_at=timezone.now() + timedelta(days=days) if days is not None else None,
    )
    call_command('check_workflow_failures', stdout=StringIO())
    assert NotificationModel.objects.exists() == expected
    if expected:
        notification = NotificationModel.objects.get()
        assert notification.message_type == 'WORKFLOW_APPROVAL_OVERDUE'
        approval.status = 'approved'
        approval.save()
        call_command('check_workflow_failures', stdout=StringIO())
        assert notification.statuses.filter(status='SOLV').exists()


def test_backup_failure_preserves_original_error(monkeypatch, settings, tmp_path):
    from management.management.commands import trustpointbackup

    settings.BACKUP_FILE_PATH = tmp_path
    backup = Mock(side_effect=CommandError('sensitive backend error'))
    monkeypatch.setattr(trustpointbackup, 'call_command', backup)
    monkeypatch.setattr(trustpointbackup, 'write_backup_manifest', lambda path: path.with_suffix('.json'))
    with pytest.raises(CommandError, match='sensitive backend error'):
        call_command('trustpointbackup', filename='test.dump.gz', stdout=StringIO())
    notification = NotificationModel.objects.get(event='BACKUP_FAILED')
    assert notification.notification_type == 'CRI'
    assert 'sensitive' not in str(notification.message_data)
    backup.side_effect = None
    call_command('trustpointbackup', filename='test.dump.gz', stdout=StringIO())
    assert notification.statuses.filter(status='SOLV').exists()


def test_backup_directory_failure_is_reported(tmp_path, settings):
    from management.views.backup import create_db_backup

    path = tmp_path / 'not-a-directory'
    path.write_text('existing file')
    settings.BACKUP_FILE_PATH = path
    with pytest.raises(OSError):
        create_db_backup()
    notification = NotificationModel.objects.get(event='BACKUP_FAILED')
    assert notification.message_type == 'BACKUP_FAILED'
    assert path.read_text() == 'existing file'


@pytest.mark.parametrize('failure_stage', ['connect', 'upload'])
def test_sftp_backup_failure_and_recovery(monkeypatch, settings, tmp_path, failure_stage):
    from management.views import backup
    from util.sftp import SftpError

    settings.BACKUP_FILE_PATH = tmp_path
    monkeypatch.setattr(backup, 'create_db_backup', lambda: 'backup.dump.gz')
    monkeypatch.setattr(backup.BackupOptions.objects, 'get', lambda **kwargs: Mock(remote_directory='/backups/'))
    monkeypatch.setattr(backup.messages, 'error', Mock())
    monkeypatch.setattr(backup.messages, 'success', Mock())
    client = Mock(remote_directory='/backups/')
    factory = Mock(return_value=client)
    monkeypatch.setattr(backup, 'SftpClient', factory)
    failure = SftpError('sensitive connection details')
    if failure_stage == 'connect':
        factory.side_effect = failure
    else:
        client.upload_file.side_effect = failure
    view = backup.BackupManageView()
    view.success_url = '/management/backups/'
    response = view._handle_create_sftp_backup(Mock())
    assert response.status_code == 302
    notification = NotificationModel.objects.get(event='BACKUP_UPLOAD_FAILED')
    assert notification.notification_type == 'CRI'
    assert 'sensitive' not in str(notification.message_data)
    factory.side_effect = None
    client.upload_file.side_effect = None
    view._handle_create_sftp_backup(Mock())
    assert notification.statuses.filter(status='SOLV').exists()


def test_overdue_cycle_is_detected_by_web_request(config):
    config.notification_cycle_enabled = True
    config.notification_cycle_interval_hours = 1
    config.last_notification_check_started_at = timezone.now() - timedelta(hours=3)
    config.save()
    request = Mock(user=Mock(is_authenticated=True))
    for _ in range(2):
        payload = notification_alerts(request)
    notification = NotificationModel.objects.get(event='NOTIFICATION_CHECK_OVERDUE')
    assert payload['notification_alert_warning_count'] == 1
    config.last_notification_check_started_at = timezone.now() + timedelta(hours=1)
    config.save()
    check_notification_cycle()
    assert notification.statuses.filter(status='SOLV').exists()
    assert not notification.statuses.filter(status='NEW').exists()


@pytest.mark.parametrize('enabled', [False, True])
def test_disabled_cycle_does_not_warn(config, enabled):
    config.enabled = enabled
    config.notification_cycle_enabled = False
    config.save()
    check_notification_cycle()
    assert not NotificationModel.objects.exists()


def test_cycle_grace_and_missing_schedule(config, monkeypatch):
    now = timezone.now()
    monkeypatch.setattr('django.utils.timezone.now', lambda: now)
    config.notification_cycle_enabled = True
    config.notification_cycle_interval_hours = 1 / 60
    config.last_notification_check_started_at = now - timedelta(minutes=4)
    config.save()
    check_notification_cycle()
    assert not NotificationModel.objects.exists()
    config.last_notification_check_started_at = None
    config.save()
    check_notification_cycle()
    assert NotificationModel.objects.get().message_type == 'NOTIFICATION_CHECK_OVERDUE'


def test_notifications_disabled(config, workflow, monkeypatch):
    config.enabled = False
    config.save()
    workflow.status = 'error'
    workflow.save()
    TrustpointUser.objects.create_user(username='blocked', blocked_by_failed_logins=True)
    probe = Mock()
    monkeypatch.setattr(
        'management.management.commands.check_crypto_backend.get_active_backend_capability_report', probe
    )
    for command in (
        'check_account_lockouts',
        'check_workflow_failures',
        'check_crypto_backend',
        'check_api_credential_validity',
    ):
        call_command(command, stdout=StringIO())
    assert not NotificationModel.objects.exists()
    probe.assert_not_called()


def test_alert_failure_does_not_replace_operation_error(monkeypatch, caplog):
    monkeypatch.setattr(NotificationModel.objects, 'create', Mock(side_effect=RuntimeError('storage failed')))
    notify_operational_issue(
        'TEST',
        NotificationModel.NotificationMessageType.ACCOUNT_LOCKED,
        NotificationModel.NotificationTypes.WARNING,
        {'username': 'user'},
    )
    assert 'Unable to record operational notification TEST' in caplog.text


def test_alert_escapes_html():
    notify_operational_issue(
        'TEST',
        NotificationModel.NotificationMessageType.ACCOUNT_LOCKED,
        NotificationModel.NotificationTypes.WARNING,
        {'username': '<script>bad</script>'},
    )
    notification = NotificationModel.objects.get()
    assert '<script>' not in notification.long_translated
    assert '&lt;script&gt;' in notification.long_translated


def test_scheduled_alert_storage_error_reaches_caller(monkeypatch):
    TrustpointUser.objects.create_user(username='locked', blocked_by_failed_logins=True)
    monkeypatch.setattr(NotificationModel.objects, 'create', Mock(side_effect=RuntimeError('storage failed')))
    with pytest.raises(RuntimeError, match='storage failed'):
        call_command('check_account_lockouts', stdout=StringIO())


def test_scheduled_recovery_storage_error_reaches_caller(monkeypatch):
    from management.notifications import resolve_operational_issue

    notify_operational_issue(
        'TEST',
        NotificationModel.NotificationMessageType.ACCOUNT_LOCKED,
        NotificationModel.NotificationTypes.WARNING,
        {'username': 'alice'},
    )
    monkeypatch.setattr(
        'management.notifications.NotificationStatus.objects.get_or_create',
        Mock(side_effect=RuntimeError('storage failed')),
    )
    with pytest.raises(RuntimeError, match='storage failed'):
        resolve_operational_issue('TEST', strict=True)
    assert NotificationModel.objects.get().statuses.filter(status='NEW').exists()


def test_authentication_failure_pauses_until_operator_retries(crypto_probe, rf):
    from crypto.domain.errors import AuthenticationError
    from management.views.notifications import NotificationMarkSolvedView

    crypto_probe.side_effect = AuthenticationError('sensitive PIN details')
    for _ in range(2):
        call_command('check_crypto_backend', stdout=StringIO())
    assert crypto_probe.call_count == 1
    notification = NotificationModel.objects.get(event='CRYPTO_BACKEND_UNAVAILABLE')
    assert notification.message_data['authentication_failed'] is True
    assert 'sensitive' not in str(notification.message_data)
    NotificationMarkSolvedView().post(rf.post('/'), pk=notification.pk)
    crypto_probe.side_effect = None
    crypto_probe.return_value.available = True
    call_command('check_crypto_backend', stdout=StringIO())
    assert crypto_probe.call_count == 2
    assert notification.statuses.filter(status='SOLV').exists()


def test_unblock_then_relock_is_unread_without_polling(rf, monkeypatch):
    from management.models import AccountSecurityConfig
    from users.management_backend import TrustpointModelBackend
    from users.views import TrustpointProfileView

    user = TrustpointUser.objects.create_user(username='relock-user', password='valid-password')
    AccountSecurityConfig.objects.update_or_create(pk=1, defaults={'failed_login_attempts': 1})
    backend = TrustpointModelBackend()
    backend.authenticate(None, username=user.username, password='wrong')
    notification = NotificationModel.objects.get(event=f'ACCOUNT_LOCKED_{user.pk}')
    notification.statuses.clear()
    request = rf.post('/users/profile/', {'form_name': 'unblock_failed_login'})
    request.user = Mock(is_authenticated=True, pk=-1)
    request.user.has_perm.return_value = True
    monkeypatch.setattr('users.views.messages.success', Mock())
    response = TrustpointProfileView.as_view()(request, pk=user.pk)
    assert response.status_code == 302
    assert notification.statuses.filter(status='SOLV').exists()
    backend.authenticate(None, username=user.username, password='wrong')
    assert not notification.statuses.filter(status='SOLV').exists()
    assert notification.statuses.filter(status='NEW').exists()


def test_recovery_is_solved_in_details():
    from management.notifications import resolve_operational_issue
    from management.views.notifications import NotificationDetailsView

    notify_operational_issue(
        'TEST',
        NotificationModel.NotificationMessageType.ACCOUNT_LOCKED,
        NotificationModel.NotificationTypes.WARNING,
        {'username': 'alice'},
    )
    resolve_operational_issue('TEST')
    view = NotificationDetailsView()
    view.object = NotificationModel.objects.get(event='TEST')
    assert view.get_context_data()['is_solved'] is True


def test_names_escape_once_at_render_time():
    from django.template import Context, Template

    notify_operational_issue(
        'TEST',
        NotificationModel.NotificationMessageType.ACCOUNT_LOCKED,
        NotificationModel.NotificationTypes.WARNING,
        {'username': 'Alice & Bob <admin>'},
    )
    notification = NotificationModel.objects.get(event='TEST')
    assert notification.message_data['username'] == 'Alice & Bob <admin>'
    assert notification.short_translated == 'User account Alice & Bob <admin> is locked'
    html = Template('{{ n.short_translated }} {{ n.long_translated|safe }}').render(Context({'n': notification}))
    assert 'Alice &amp; Bob &lt;admin&gt;' in html
    assert '&amp;amp;' not in html
    assert '<admin>' not in html


def test_unchanged_workflow_history_does_not_repeat_per_item_queries(workflow, django_assert_num_queries):
    from management.views.notifications import NotificationMarkSolvedView
    from django.test import RequestFactory

    for _ in range(10):
        Workflow2Instance.objects.create(definition=workflow.definition, event_json={}, status='error')
    Workflow2Approval.objects.create(
        instance=workflow, step_id='finished', status='approved', expires_at=timezone.now() - timedelta(days=1)
    )
    call_command('check_workflow_failures', stdout=StringIO())
    notification = NotificationModel.objects.first()
    NotificationMarkSolvedView().post(RequestFactory().post('/'), pk=notification.pk)
    with django_assert_num_queries(5):
        call_command('check_workflow_failures', stdout=StringIO())
    assert notification.statuses.filter(status='SOLV').exists()
    assert NotificationModel.objects.count() == 10


def test_existing_statuses_and_escaped_names_are_migrated():
    from importlib import import_module
    from django.apps import apps
    from django.db import connection
    from management.models import NotificationStatus

    migration = import_module('management.migrations.0012_normalize_notification_status_and_data')
    legacy = NotificationStatus.objects.create(status='SOLVED')
    solved, _ = NotificationStatus.objects.get_or_create(status='SOLV')
    first = NotificationModel.objects.create(
        message_type='ACCOUNT_LOCKED', message_data={'username': 'Alice &amp; Bob &lt;admin&gt;'}
    )
    second = NotificationModel.objects.create(
        message_type='USER_CERT_EXPIRED',
        message_data={'username': 'alice', 'identifier': 'literal &amp;amp;', 'common_name': 'literal &amp;'},
    )
    first.statuses.add(legacy)
    second.statuses.add(legacy, solved)
    editor = SimpleNamespace(connection=connection)
    migration.normalize_notifications(apps, editor)
    assert not NotificationStatus.objects.filter(status='SOLVED').exists()
    assert first.statuses.get().status == 'SOLV'
    assert second.statuses.get().status == 'SOLV'
    first.refresh_from_db()
    second.refresh_from_db()
    assert first.message_data['username'] == 'Alice & Bob <admin>'
    assert second.message_data['identifier'] == 'literal &amp;'
    assert second.message_data['common_name'] == 'literal &amp;'
    assert '&lt;admin&gt;' in first.long_translated
    migration.restore_escaped_data(apps, editor)
    first.refresh_from_db()
    assert first.message_data['username'] == 'Alice &amp; Bob &lt;admin&gt;'


@pytest.mark.parametrize('method', ['get', 'post', 'delete'])
def test_unresolved_authentication_alert_cannot_be_deleted(crypto_probe, rf, method):
    from crypto.domain.errors import AuthenticationError
    from django.core.exceptions import PermissionDenied
    from management.views.notifications import NotificationDeleteView

    crypto_probe.side_effect = AuthenticationError('incorrect PIN')
    call_command('check_crypto_backend', stdout=StringIO())
    notification = NotificationModel.objects.get(event='CRYPTO_BACKEND_UNAVAILABLE')
    assert not notification.can_delete
    request = getattr(rf, method)('/')
    request.user = Mock(is_authenticated=True)
    request.user.has_perm.return_value = True
    with pytest.raises(PermissionDenied, match='mark this alert solved'):
        NotificationDeleteView.as_view()(request, pk=notification.pk)
    assert NotificationModel.objects.filter(pk=notification.pk).exists()
    call_command('check_crypto_backend', stdout=StringIO())
    assert crypto_probe.call_count == 1


@pytest.mark.parametrize('authentication_failed', [False, True])
def test_solved_and_non_authentication_alerts_can_be_deleted(rf, authentication_failed):
    from management.models import NotificationStatus
    from management.views.notifications import NotificationDeleteView

    notification = NotificationModel.objects.create(
        event='CRYPTO_BACKEND_UNAVAILABLE', message_data={'authentication_failed': authentication_failed}
    )
    if authentication_failed:
        solved, _ = NotificationStatus.objects.get_or_create(status='SOLV')
        notification.statuses.add(solved)
    assert notification.can_delete
    request = rf.post('/')
    request.user = Mock(is_authenticated=True)
    request.user.has_perm.return_value = True
    assert NotificationDeleteView.as_view()(request, pk=notification.pk).status_code == 302
    assert not NotificationModel.objects.filter(pk=notification.pk).exists()


def test_older_backup_success_does_not_clear_newer_failure(monkeypatch, settings, tmp_path):
    from management.management.commands import trustpointbackup
    from django.core.files import locks

    settings.BACKUP_FILE_PATH = tmp_path

    def backup(name, *args):
        filename = args[1]
        if filename == 'newer.dump.gz':
            raise CommandError('newer backup failed')
        (tmp_path / filename).write_bytes(b'backup')

    monkeypatch.setattr(trustpointbackup, 'call_command', backup)
    monkeypatch.setattr(trustpointbackup, 'write_backup_manifest', lambda path: path.with_suffix('.json'))
    notify = trustpointbackup.notify_operational_issue
    resolve = trustpointbackup.resolve_operational_issue

    def assert_locked(callback):
        def report(*args, **kwargs):
            with (tmp_path / '.backup.lock').open('a') as other_lock:
                assert not locks.lock(other_lock, locks.LOCK_EX | locks.LOCK_NB)
            return callback(*args, **kwargs)

        return report

    monkeypatch.setattr(trustpointbackup, 'notify_operational_issue', assert_locked(notify))
    monkeypatch.setattr(trustpointbackup, 'resolve_operational_issue', assert_locked(resolve))

    class AfterBackupLockIsReleased(StringIO):
        def write(self, value):
            if 'Backup manifest written' in value:
                with pytest.raises(CommandError, match='newer backup failed'):
                    call_command('trustpointbackup', filename='newer.dump.gz', stdout=StringIO())
            return super().write(value)

    call_command('trustpointbackup', filename='older.dump.gz', stdout=AfterBackupLockIsReleased())
    notification = NotificationModel.objects.get(event='BACKUP_FAILED')
    assert notification.statuses.filter(status='NEW').exists()
    assert not notification.statuses.filter(status='SOLV').exists()


def test_backup_view_does_not_repeat_a_reported_failure(monkeypatch):
    from management.views import backup

    command = Mock(side_effect=CommandError('already reported by command'))
    monkeypatch.setattr(backup, 'call_command', command)
    report = Mock()
    monkeypatch.setattr(backup, 'notify_operational_issue', report)
    with pytest.raises(CommandError, match='already reported'):
        backup.create_db_backup()
    report.assert_not_called()
