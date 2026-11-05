# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Regressions for management authorization, credential safety, and scheduling."""

from io import StringIO
from pathlib import Path
import subprocess
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from django.contrib.auth.models import Group, Permission
from django.contrib.messages.storage.fallback import FallbackStorage
from django.core.exceptions import PermissionDenied
from django.core.management import CommandError, call_command
from django.test import RequestFactory
from django.urls import reverse
from django_q.models import Schedule
from rest_framework.test import APIClient

from management.forms import TlsAddFileImportPkcs12Form, TlsAddFileImportSeparateFilesForm
from management.models import NotificationConfig, NotificationModel, NotificationStatus
from management.serializer.role import RoleSerializer
from management.views import notifications, tls
from management.views.backend_configuration import BackendConfigurationView
from management.views.logging import LoggingViewSet
from management.views.service_accounts import (
    generate_credential_view,
    revoke_credential_view,
    service_account_created_view,
)
from management.views.settings import ChangeLogLevelView
from pki.models import CredentialModel
from pki.models.truststore import ActiveTrustpointTlsServerCredentialModel
from users.form import GroupPermissionForm
from users.models import BuiltinRole, GroupProfile, ServiceAccountCredential, TrustpointUser

pytestmark = pytest.mark.django_db


@pytest.fixture
def manager():
    role = Group.objects.create(name='Audit manager')
    return TrustpointUser.objects.create_user(username='audit-manager', role=role)


def grant(user, codename):
    user.role.permissions.add(Permission.objects.get(codename=codename))


def request(user, method='post', data=None):
    value = getattr(RequestFactory(), method)('/', data or {})
    value.user = user
    value.session = {}
    value._messages = FallbackStorage(value)
    return value


@pytest.mark.parametrize(
    'view,form',
    [
        (tls.GenerateTlsCertificateView, None),
        (tls.TlsAddFileImportPkcs12View, TlsAddFileImportPkcs12Form),
        (tls.TlsAddFileImportSeparateFilesView, TlsAddFileImportSeparateFilesForm),
    ],
)
def test_tls_permission_checked_before_form_validation(manager, monkeypatch, view, form):
    validate = Mock(side_effect=AssertionError('Unauthorized input reached validation'))
    if form is not None:
        monkeypatch.setattr(form, 'is_valid', validate)
    with pytest.raises(PermissionDenied):
        view.as_view()(request(manager))
    validate.assert_not_called()


@pytest.mark.parametrize(
    'view,data',
    [
        (ChangeLogLevelView, {'loglevel': 'DEBUG'}),
        (BackendConfigurationView, {'action': 'reprobe'}),
        (notifications.NotificationsListView, {'mark_all_read': '1'}),
    ],
)
def test_management_writes_require_permission(manager, view, data):
    with pytest.raises(PermissionDenied):
        view.as_view()(request(manager, data=data))


def test_tls_api_scopes_credentials_and_preserves_active(manager):
    grant(manager, 'manage_tls_webserver_configuration')
    api = APIClient()
    api.force_authenticate(manager)
    other = CredentialModel.objects.create(credential_type=CredentialModel.CredentialTypeChoice.SIGNER)
    active = CredentialModel.objects.create(credential_type=CredentialModel.CredentialTypeChoice.TRUSTPOINT_TLS_SERVER)
    ActiveTrustpointTlsServerCredentialModel.objects.create(pk=1, credential=active)
    other_url = reverse('tls-detail', args=[other.pk])
    assert api.patch(other_url, {'credential_type': 0}, format='json').status_code == 404
    assert api.delete(other_url).status_code == 404
    url = reverse('tls-detail', args=[active.pk])
    assert api.patch(url, {'credential_type': 5}, format='json').status_code == 200
    active.refresh_from_db()
    assert active.credential_type == CredentialModel.CredentialTypeChoice.TRUSTPOINT_TLS_SERVER
    assert api.delete(url).status_code == 400
    assert ActiveTrustpointTlsServerCredentialModel.objects.get(pk=1).credential_id == active.pk
    assert CredentialModel.objects.filter(pk=other.pk).exists()
    created = api.post(reverse('tls-list'), {'credential_type': 5}, format='json')
    assert created.status_code == 201
    assert created.data['credential_type'] == CredentialModel.CredentialTypeChoice.TRUSTPOINT_TLS_SERVER


def test_tls_web_operations_reject_unrelated_certificates(manager, credential_instance, monkeypatch):
    grant(manager, 'manage_tls_webserver_configuration')
    credential = credential_instance['credential']
    view = tls.TlsBulkDeleteConfirmView()
    view.setup(request(manager), pks=str(credential.certificate_id))
    assert not view.get_queryset().exists()
    update = Mock()
    monkeypatch.setattr(tls, 'UpdateTlsCommand', update)
    tls.ActivateTlsServerView.as_view()(request(manager), pk=credential.certificate_id)
    update.assert_not_called()
    assert not ActiveTrustpointTlsServerCredentialModel.objects.exists()


def test_tls_bulk_delete_removes_selected_certificate(manager, credential_instance):
    grant(manager, 'manage_tls_webserver_configuration')
    credential = credential_instance['credential']
    credential.credential_type = CredentialModel.CredentialTypeChoice.TRUSTPOINT_TLS_SERVER
    credential.save()
    cert = credential.certificate
    certificate_pk, credential_pk = cert.pk, credential.pk
    view = tls.TlsBulkDeleteConfirmView()
    view.setup(request(manager), pks=str(certificate_pk))
    response = view.form_valid(None)
    assert response.status_code == 302
    assert not CredentialModel.objects.filter(pk=credential_pk).exists()
    assert not type(cert).objects.filter(pk=certificate_pk).exists()


@pytest.mark.parametrize('editor', ['form', 'api'])
@pytest.mark.parametrize('enabled', [False, True])
def test_role_grants_reach_existing_users(manager, editor, enabled):
    GroupProfile.objects.create(group=manager.role, grants_superuser=not enabled, grants_staff=not enabled)
    service = TrustpointUser.objects.create_user(
        username='audit-service',
        role=manager.role,
        account_type=TrustpointUser.AccountType.SERVICE,
    )
    data = {'grants_staff': enabled, 'grants_superuser': enabled}
    if editor == 'api':
        form = RoleSerializer(manager.role, data=data, partial=True)
    else:
        form = GroupPermissionForm({'name': manager.role.name, **data}, instance=manager.role)
    assert form.is_valid(), form.errors
    form.save()
    manager.refresh_from_db()
    service.refresh_from_db()
    assert manager.is_superuser is enabled
    assert manager.is_staff is enabled
    assert not service.is_staff and not service.is_superuser


def test_notification_scheduling_replaces_existing_cycles():
    config = NotificationConfig.get()
    config.enabled = config.notification_cycle_enabled = True
    config.save()
    Schedule.objects.create(func='management.tasks.execute_all_notifications', schedule_type='O')
    config.schedule_next_notification_check()
    config.schedule_next_notification_check()
    assert Schedule.objects.filter(func='management.tasks.execute_all_notifications').count() == 1
    # A stale in-flight worker must not restart a disabled cycle.
    NotificationConfig.objects.filter(pk=config.pk).update(enabled=False)
    before = Schedule.objects.get(func='management.tasks.execute_all_notifications').pk
    config.schedule_next_notification_check()
    assert Schedule.objects.get(func='management.tasks.execute_all_notifications').pk == before


@pytest.mark.parametrize(
    'view',
    [
        notifications.NotificationMarkSolvedView,
        notifications.NotificationToggleReadView,
        notifications.RefreshNotificationsView,
    ],
)
def test_notification_mutations_reject_get(manager, view):
    grant(manager, 'manage_notifications')
    assert view.as_view()(request(manager, 'get'), pk=1).status_code == 405


def test_notification_status_changes_require_post(manager):
    grant(manager, 'manage_notifications')
    notification = NotificationModel.objects.create(event='audit-test', message_type='WELCOME')
    new, _ = NotificationStatus.objects.get_or_create(status='NEW')
    notification.statuses.add(new)
    notifications.NotificationToggleReadView.as_view()(request(manager), pk=notification.pk)
    assert not notification.statuses.filter(status='NEW').exists()
    notifications.NotificationMarkSolvedView.as_view()(request(manager), pk=notification.pk)
    assert notification.statuses.filter(status='SOLVED').exists()


def test_service_manager_rotates_and_revokes_with_app_permission(manager):
    grant(manager, 'manage_service_accounts')
    service = TrustpointUser.objects.create_user(
        username='managed-service',
        account_type=TrustpointUser.AccountType.SERVICE,
        role=BuiltinRole.get_service_group(),
    )
    assert generate_credential_view(request(manager, 'get'), service.pk).status_code == 405
    assert not ServiceAccountCredential.objects.filter(service_account=service).exists()
    submission = request(manager)
    assert generate_credential_view(submission, service.pk).status_code == 302
    secret = submission.session['new_service_account']['secret']
    submission.method = 'GET'
    display = service_account_created_view(submission)
    assert display.status_code == 200
    assert secret.encode() in display.content
    assert 'new_service_account' not in submission.session
    credential = ServiceAccountCredential.objects.get(service_account=service)
    assert revoke_credential_view(request(manager), credential.pk).status_code == 302
    credential.refresh_from_db()
    assert not credential.is_active


def test_log_download_preserves_bytes_and_streams_blocks(manager, tmp_path, monkeypatch):
    import management.views.logging as log_views

    content = b'\xff' + b'x' * 10000
    (tmp_path / 'trustpoint.log').write_bytes(content)
    monkeypatch.setattr(log_views, 'LOG_DIR_PATH', tmp_path)
    response = LoggingViewSet().download(request(manager, 'get'), 'trustpoint.log')
    try:
        chunks = list(response.streaming_content)
        assert b''.join(chunks) == content
        assert len(chunks) < 10
    finally:
        response.close()


@pytest.mark.parametrize('missing_chain', [False, True])
def test_failed_tls_update_restores_staging_files(tmp_path, monkeypatch, missing_chain):
    import management.management.commands.update_tls as command

    paths = [tmp_path / name for name in ('key', 'cert', 'chain')]
    for name, path in zip(('NGINX_KEY_PATH', 'NGINX_CERT_PATH', 'NGINX_CERT_CHAIN_PATH'), paths, strict=True):
        monkeypatch.setattr(command, name, path)
        path.write_bytes(b'previous-' + path.name.encode())
    if missing_chain:
        paths[-1].unlink()
    before = {p: p.read_bytes() if p.exists() else None for p in paths}
    monkeypatch.setattr(command, 'SCRIPT_UPDATE_TLS_SERVER_CREDENTIAL', Path(__file__))
    credential = Mock()
    credential.get_private_key_serializer().as_pkcs8_pem.return_value = b'new-key'
    credential.get_certificate_serializer().as_pem.return_value = b'new-cert'
    credential.get_certificate_chain_serializer().as_pem.return_value = b'new-chain'
    monkeypatch.setattr(
        command.ActiveTrustpointTlsServerCredentialModel.objects,
        'select_for_update',
        lambda: SimpleNamespace(get=lambda **kwargs: SimpleNamespace(credential=credential)),
    )
    monkeypatch.setattr(command.subprocess, 'run', Mock(return_value=SimpleNamespace(returncode=1, stderr='failed')))
    output = StringIO()
    with pytest.raises(CommandError):
        call_command('update_tls', stdout=output)
    assert 'successful' not in output.getvalue()
    assert {p: p.read_bytes() if p.exists() else None for p in paths} == before


def test_failed_tls_activation_restores_active_record(manager, monkeypatch):
    grant(manager, 'manage_tls_webserver_configuration')
    previous = CredentialModel.objects.create(credential_type=0)
    candidate = CredentialModel.objects.create(credential_type=0)
    ActiveTrustpointTlsServerCredentialModel.objects.create(pk=1, credential=previous)
    monkeypatch.setattr(tls.CredentialModel.objects, 'get', Mock(return_value=candidate))
    monkeypatch.setattr(tls.UpdateTlsCommand, 'handle', Mock(side_effect=CommandError('failed')))
    tls.ActivateTlsServerView.as_view()(request(manager), pk=123)
    assert ActiveTrustpointTlsServerCredentialModel.objects.get(pk=1).credential_id == previous.pk


@pytest.mark.parametrize('failure', ['validation', 'reload', None])
def test_privileged_tls_installer_restores_installed_files(tmp_path, failure):
    script = Path(__file__).resolve().parents[3] / 'docker/trustpoint/wizard/internal/update_tls.sh'
    installed, staging, binaries = (tmp_path / name for name in ('installed', 'staging', 'bin'))
    for folder in (installed, staging, binaries):
        folder.mkdir()
    names = ('nginx-tls-server-key.key', 'nginx-tls-server-cert.pem', 'nginx-tls-server-cert-chain.pem')
    for name in names:
        (installed / name).write_text('previous')
    for name in names[:2]:
        (staging / name).write_text('candidate')
    nginx = binaries / 'nginx'
    nginx.write_text(
        '#!/bin/bash\n'
        + (
            'exit 1\n'
            if failure == 'validation'
            else 'if [ "$1" = "-s" ]; then exit 1; fi\nexit 0\n'
            if failure == 'reload'
            else 'exit 0\n'
        )
    )
    nginx.chmod(0o755)
    pid = tmp_path / 'nginx.pid'
    import os

    pid.write_text(str(os.getpid()))
    source = script.read_text().replace('/etc/trustpoint/tls/', str(installed))
    source = source.replace('/var/www/html/trustpoint/docker/trustpoint/nginx/tls', str(staging))
    source = source.replace('/run/nginx.pid', str(pid)).replace('DELAY=2', 'DELAY=0')
    result = subprocess.run(
        ['bash', '-c', source],
        env={**os.environ, 'PATH': f'{binaries}:{os.environ["PATH"]}'},
        capture_output=True,
        text=True,
    )
    assert (result.returncode != 0) is (failure is not None), result.stdout + result.stderr
    if failure:
        assert all((installed / name).read_text() == 'previous' for name in names)
    else:
        assert all((installed / name).read_text() == 'candidate' for name in names[:2])
        assert not (installed / names[-1]).exists()


@pytest.mark.django_db(transaction=True)
@pytest.mark.parametrize('operation', ['delete', 'demote'])
def test_concurrent_admin_removal_keeps_one_admin(monkeypatch, operation):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Barrier

    from django.db import close_old_connections, connection
    from rest_framework.test import APIRequestFactory, force_authenticate

    from management.views import user_management

    if connection.vendor != 'postgresql':
        pytest.skip('Row-lock concurrency requires PostgreSQL')
    admin_role, _ = Group.objects.get_or_create(name=BuiltinRole.ADMIN)
    GroupProfile.objects.update_or_create(
        group=admin_role,
        defaults={'grants_superuser': True, 'grants_staff': True},
    )
    users = [TrustpointUser.objects.create_user(username=f'concurrent-admin-{i}', role=admin_role) for i in range(2)]
    plain = Group.objects.create(name='Concurrent viewer')
    barrier = Barrier(2)
    lock = user_management.lock_admin_role

    def synchronized_lock():
        barrier.wait(timeout=10)
        lock()

    monkeypatch.setattr(user_management, 'lock_admin_role', synchronized_lock)

    def remove(user):
        close_old_connections()
        try:
            if operation == 'delete':
                req = APIRequestFactory().delete('/')
                view = user_management.UserViewSet.as_view({'delete': 'destroy'})
            else:
                req = APIRequestFactory().patch('/', {'role': plain.pk}, format='json')
                view = user_management.UserViewSet.as_view({'patch': 'partial_update'})
            force_authenticate(req, user=user)
            return view(req, pk=user.pk).status_code
        finally:
            close_old_connections()

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(remove, users))
    assert sorted(results) == ([204, 400] if operation == 'delete' else [200, 400])
    assert TrustpointUser.objects.filter(role=admin_role).count() == 1


@pytest.mark.django_db(transaction=True)
@pytest.mark.parametrize('editor', ['form', 'api'])
def test_new_account_and_role_edit_use_the_same_lock_order(editor):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Event, local
    from unittest.mock import patch

    from django.db import connection, connections
    from django.db.models import Model, QuerySet

    if connection.vendor != 'postgresql':
        pytest.skip('Row-lock concurrency requires PostgreSQL')
    role = Group.objects.create(name='Concurrent account role')
    GroupProfile.objects.create(group=role, grants_staff=True, grants_superuser=True)
    creation_ready, editor_ready = Event(), Event()
    thread_state = local()
    original_save = Model.save
    original_lock = QuerySet.select_for_update

    def coordinate_save(instance, *args, **kwargs):
        if isinstance(instance, TrustpointUser):
            creation_ready.set()
            assert editor_ready.wait(timeout=10)
        elif isinstance(instance, GroupProfile) and getattr(thread_state, 'editing', False):
            editor_ready.set()
        return original_save(instance, *args, **kwargs)

    def coordinate_lock(queryset, *args, **kwargs):
        if queryset.model is GroupProfile and getattr(thread_state, 'editing', False):
            editor_ready.set()
        return original_lock(queryset, *args, **kwargs)

    def create_account():
        try:
            user = TrustpointUser(username='concurrent-account', role_id=role.pk)
            user.save()
            return user.pk
        finally:
            connections.close_all()

    def edit_role():
        try:
            assert creation_ready.wait(timeout=10)
            thread_state.editing = True
            current = Group.objects.get(pk=role.pk)
            data = {'name': 'Renamed account role', 'grants_staff': False, 'grants_superuser': False}
            form = (
                GroupPermissionForm(data, instance=current)
                if editor == 'form'
                else RoleSerializer(current, data=data, partial=True)
            )
            assert form.is_valid(), form.errors
            form.save()
        finally:
            connections.close_all()

    with patch.object(Model, 'save', coordinate_save), patch.object(QuerySet, 'select_for_update', coordinate_lock):
        with ThreadPoolExecutor(max_workers=2) as pool:
            created = pool.submit(create_account)
            edited = pool.submit(edit_role)
            user_pk = created.result(timeout=20)
            edited.result(timeout=20)
    user = TrustpointUser.objects.get(pk=user_pk)
    assert user.role.name == 'Renamed account role'
    assert not user.is_staff and not user.is_superuser
    assert list(user.groups.all()) == [user.role]
