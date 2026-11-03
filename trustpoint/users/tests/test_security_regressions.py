# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Regression checks for user authentication and permission changes."""

import hashlib
from datetime import timedelta
from io import StringIO
from unittest.mock import patch

import pytest
from django.contrib.auth import BACKEND_SESSION_KEY
from django.contrib.auth.models import Group, Permission
from django.core.management import call_command
from django.urls import reverse
from django.utils import timezone
from rest_framework.test import APIClient

from management.models import PasswordPolicy
from management.serializer.role import RoleSerializer
from users.form import GroupPermissionForm
from users.management_backend import INTERACTIVE_BACKEND
from users.models import BuiltinRole, GroupProfile, ServiceAccountCredential, TrustpointUser

pytestmark = pytest.mark.django_db
PASSWORD = 'AuditPassword123!'


@pytest.fixture(autouse=True)
def operational_policy(settings):
    settings.TRUSTPOINT_IS_OPERATIONAL = True
    settings.TRUSTPOINT_IS_BOOTSTRAP = False
    PasswordPolicy.objects.update_or_create(pk=1, defaults={'require_otp': False})


def test_enabling_otp_challenges_an_existing_password_session(client):
    user = TrustpointUser.objects.create_user(username='password-session', password=PASSWORD)
    response = client.post(reverse('users:login'), {'username': user.username, 'password': PASSWORD})
    assert response.status_code == 302
    assert client.session[BACKEND_SESSION_KEY] == INTERACTIVE_BACKEND
    PasswordPolicy.objects.filter(pk=1).update(require_otp=True)

    response = client.get(reverse('users:profile'))

    assert response.status_code == 302
    assert reverse('users:login') in response.url
    assert '_auth_user_id' not in client.session


def test_rejected_certificate_allows_fresh_password_login(client):
    user = TrustpointUser.objects.create_user(username='certificate-fallback', password=PASSWORD)
    assert client.login(username=user.username, password=PASSWORD)
    session = client.session
    session['rejected_client_certificate'] = hashlib.sha256(b'rejected').hexdigest()
    session.save()

    response = client.get(reverse('users:profile'), HTTP_SSL_CLIENT_CERT='rejected')

    assert response.status_code == 200
    assert int(client.session['_auth_user_id']) == user.pk


@pytest.mark.parametrize('writer', ['form', 'serializer'])
def test_role_grant_changes_update_assigned_users(writer):
    role = Group.objects.create(name='Custom administrator')
    GroupProfile.objects.create(group=role, grants_staff=True, grants_superuser=True)
    human = TrustpointUser.objects.create_user(username='human', role=role)
    service = TrustpointUser.objects.create_user(username='service', account_type='SERVICE', role=role)
    data = {'name': role.name, 'grants_staff': False, 'grants_superuser': False}
    writer = GroupPermissionForm(data, instance=role) if writer == 'form' else RoleSerializer(role, data=data)
    assert writer.is_valid(), writer.errors
    writer.save()

    human.refresh_from_db()
    service.refresh_from_db()
    assert not human.is_superuser and not human.is_staff
    assert not human.has_perm('users.manage_users')
    assert not service.is_superuser and not service.is_staff


def test_partial_role_save_persists_permission_flags():
    admin = TrustpointUser.objects.create_superuser(username='admin')
    admin.role = Group.objects.create(name='Viewer')
    admin.save(update_fields=['role'])
    admin.refresh_from_db()
    assert not admin.is_superuser and not admin.is_staff
    assert list(admin.groups.all()) == [admin.role]


@pytest.mark.parametrize('restriction', ['expired', 'required'])
def test_password_rotation_required_before_api_token_issuance(restriction):
    role = Group.objects.create(name='API access')
    role.permissions.add(Permission.objects.get(codename='use_rest_api'))
    user = TrustpointUser.objects.create_user(username='api-user', password=PASSWORD, role=role)
    if restriction == 'required':
        TrustpointUser.objects.filter(pk=user.pk).update(must_change_password=True)
    else:
        PasswordPolicy.objects.filter(pk=1).update(password_expiry_days=1)
        TrustpointUser.objects.filter(pk=user.pk).update(password_changed_at=timezone.now() - timedelta(days=2))

    with patch('users.oauth2_views.RefreshToken.for_user') as issue_token:
        response = APIClient().post('/api/token/', {'username': user.username, 'password': PASSWORD}, format='json')

    assert response.status_code == 401
    assert response.data['detail'].code == 'password_change_required'
    issue_token.assert_not_called()


def test_service_role_provisioning_and_lookup_preserve_permissions():
    call_command('create_builtin_groups', stdout=StringIO())
    role = BuiltinRole.get_service_group()
    assert set(role.permissions.values_list('codename', flat=True)) == {'use_rest_api'}
    extra = Permission.objects.get(codename='manage_devices')
    role.permissions.add(extra)
    BuiltinRole.get_service_group()
    TrustpointUser.objects.create_user(username='new-service', account_type='SERVICE')
    assert role.permissions.filter(pk=extra.pk).exists()
    role.permissions.clear()
    BuiltinRole.get_service_group()
    assert not role.permissions.exists()


@pytest.mark.parametrize('route', ['users:profile_delete', 'management:delete_user', 'users-detail'])
def test_disabled_admin_does_not_allow_deleting_final_active_admin(client, route):
    admin = TrustpointUser.objects.create_superuser(username='active-admin')
    TrustpointUser.objects.create_user(username='disabled-admin', role=admin.role, is_active=False)
    if route == 'users-detail':
        api_client = APIClient()
        api_client.force_authenticate(admin)
        response = api_client.delete(reverse(route, args=[admin.pk]))
        assert response.status_code == 400
    else:
        client.force_login(admin, backend=INTERACTIVE_BACKEND)
        kwargs = {'pk': admin.pk} if route == 'management:delete_user' else {}
        response = client.post(reverse(route, kwargs=kwargs))
        assert response.status_code == 302
    assert TrustpointUser.objects.filter(pk=admin.pk).exists()


@pytest.mark.parametrize('route', ['users:user-profile', 'management:change_role', 'users-detail'])
def test_disabled_admin_does_not_allow_demoting_final_active_admin(client, route):
    admin = TrustpointUser.objects.create_superuser(username='active-admin')
    TrustpointUser.objects.create_user(username='disabled-admin', role=admin.role, is_active=False)
    viewer = Group.objects.create(name='Viewer')
    if route == 'users-detail':
        api_client = APIClient()
        api_client.force_authenticate(admin)
        response = api_client.patch(reverse(route, args=[admin.pk]), {'role': viewer.pk}, format='json')
        assert response.status_code == 400
    else:
        client.force_login(admin, backend=INTERACTIVE_BACKEND)
        data = {'role': viewer.pk}
        if route == 'users:user-profile':
            data.update(language='en', timezone='UTC', date_format='6', theme='dark', view_mode='standard')
        response = client.post(reverse(route, kwargs={'pk': admin.pk}), data)
        assert response.status_code in {200, 302}
    admin.refresh_from_db()
    assert admin.role.name == BuiltinRole.ADMIN
    assert admin.is_superuser


def test_createsuperuser_provisions_admin_grants():
    admin = TrustpointUser.objects.create_superuser(username='fresh-admin', password=PASSWORD)
    admin.refresh_from_db()
    assert admin.is_superuser and admin.is_staff
    assert admin.has_perm('users.manage_users')


@pytest.mark.parametrize('field', ['client_id', 'client_secret'])
@pytest.mark.parametrize('value', [123, [], {}, True, None])
def test_malformed_client_credentials_return_bad_request(field, value):
    response = APIClient().post('/api/token/', {'grant_type': 'client_credentials', field: value}, format='json')
    assert response.status_code == 400
    assert response.data['error'] == 'invalid_request'


def test_profile_password_change_rejects_unchanged_password(client):
    user = TrustpointUser.objects.create_user(username='unchanged-password', password=PASSWORD)
    client.force_login(user, backend=INTERACTIVE_BACKEND)
    response = client.post(
        reverse('users:profile_password'),
        {
            'old_password': PASSWORD,
            'new_password1': PASSWORD,
            'new_password2': PASSWORD,
        },
    )
    assert response.status_code == 200
    assert 'new_password1' in response.context['form'].errors
    user.refresh_from_db()
    assert user.previous_password == ''


def test_independently_loaded_credentials_do_not_lose_usage():
    user = TrustpointUser.objects.create_user(username='service', account_type='SERVICE')
    first = ServiceAccountCredential.objects.create(service_account=user, client_id='usage', hashed_secret='unused')
    second = ServiceAccountCredential.objects.get(pk=first.pk)
    first.record_usage()
    second.record_usage()
    first.refresh_from_db()
    assert first.usage_count == 2
    assert first.last_used is not None


def test_cached_role_profile_cannot_restore_revoked_grants():
    user = TrustpointUser.objects.create_superuser(username='cached-admin')
    stale_profile = user.role.profile
    profile = GroupProfile.objects.get(pk=stale_profile.pk)
    profile.grants_staff = False
    profile.grants_superuser = False
    profile.save()
    stale_profile.is_deletion_protected = True
    stale_profile.save(update_fields=['is_deletion_protected'])
    user.save(update_fields=['last_login'])
    user.refresh_from_db()
    assert not user.is_staff and not user.is_superuser


def test_profile_rechecks_last_admin_after_form_validation(rf):
    from django.contrib.messages.storage.fallback import FallbackStorage
    from users.form import TrustpointUserProfileForm
    from users.views import TrustpointProfileView

    first = TrustpointUser.objects.create_superuser(username='first-admin')
    last = TrustpointUser.objects.create_superuser(username='last-admin')
    viewer = Group.objects.create(name='Viewer')
    form = TrustpointUserProfileForm(
        {
            'role': viewer.pk,
            'language': 'en',
            'timezone': 'UTC',
            'date_format': '6',
            'theme': 'dark',
            'view_mode': 'standard',
        },
        instance=last,
        user=last,
    )
    assert form.is_valid(), form.errors
    first.delete()
    request = rf.post('/users/profile/')
    request.user = last
    request.session = {}
    request._messages = FallbackStorage(request)
    view = TrustpointProfileView()
    view.setup(request)
    view.object = form.instance

    response = view.form_valid(form)

    assert response.status_code == 200
    assert 'role' in form.errors
    last.refresh_from_db()
    assert last.role.name == BuiltinRole.ADMIN


@pytest.mark.django_db(transaction=True)
def test_concurrent_admin_deletions_leave_one_active_admin():
    from concurrent.futures import ThreadPoolExecutor
    from threading import Barrier

    from django.db import connection, connections
    from management.views import user_management

    if not connection.features.has_select_for_update:
        pytest.skip('Requires a database with row locks, such as PostgreSQL.')
    admins = [TrustpointUser.objects.create_superuser(username=f'admin-{i}') for i in range(2)]
    barrier = Barrier(2)
    original_check = user_management.is_last_admin_user

    def synchronized_check(user, *, lock=False):
        barrier.wait(timeout=10)
        return original_check(user, lock=lock)

    def delete_admin(user):
        try:
            client = APIClient()
            client.force_authenticate(user)
            return client.delete(reverse('users-detail', args=[user.pk])).status_code
        finally:
            connections.close_all()

    with patch.object(user_management, 'is_last_admin_user', synchronized_check):
        with ThreadPoolExecutor(max_workers=2) as pool:
            statuses = list(pool.map(delete_admin, admins))
    assert sorted(statuses) == [204, 400]
    assert TrustpointUser.objects.filter(role__name=BuiltinRole.ADMIN, is_active=True).count() == 1


@pytest.mark.parametrize('restriction', ['expired', 'required'])
def test_password_rotation_blocks_existing_refresh_tokens(restriction):
    role = Group.objects.create(name='Refresh API access')
    role.permissions.add(Permission.objects.get(codename='use_rest_api'))
    user = TrustpointUser.objects.create_user(username='refresh-user', password=PASSWORD, role=role)
    client = APIClient()
    response = client.post('/api/token/', {'username': user.username, 'password': PASSWORD}, format='json')
    assert response.status_code == 200
    refresh = response.data['refresh']
    assert client.post('/api/token/refresh/', {'refresh': refresh}, format='json').status_code == 200
    if restriction == 'required':
        TrustpointUser.objects.filter(pk=user.pk).update(must_change_password=True)
    else:
        PasswordPolicy.objects.filter(pk=1).update(password_expiry_days=1)
        TrustpointUser.objects.filter(pk=user.pk).update(password_changed_at=timezone.now() - timedelta(days=2))

    response = client.post('/api/token/refresh/', {'refresh': refresh}, format='json')

    assert response.status_code == 401
    assert response.data['detail'].code == 'password_change_required'
    assert 'access' not in response.data


def test_partial_user_save_does_not_restore_a_stale_role():
    stale_user = TrustpointUser.objects.create_superuser(username='stale-role')
    current_user = TrustpointUser.objects.get(pk=stale_user.pk)
    viewer = Group.objects.create(name='Viewer')
    current_user.role = viewer
    current_user.save(update_fields=['role'])

    stale_user.last_login = timezone.now()
    stale_user.save(update_fields=['last_login'])

    stale_user.refresh_from_db()
    assert stale_user.role == viewer
    assert not stale_user.is_staff and not stale_user.is_superuser
    assert list(stale_user.groups.all()) == [viewer]
    assert stale_user.last_login is not None


def test_partial_account_type_change_clears_privileges():
    user = TrustpointUser.objects.create_superuser(username='service-transition')
    user.account_type = TrustpointUser.AccountType.SERVICE
    user.save(update_fields=['account_type'])
    user.refresh_from_db()
    assert user.account_type == TrustpointUser.AccountType.SERVICE
    assert not user.is_staff and not user.is_superuser


@pytest.mark.django_db(transaction=True)
@pytest.mark.parametrize('creating', [False, True])
def test_user_save_holds_lock_when_reading_role_grants(creating):
    from concurrent.futures import ThreadPoolExecutor

    from django.db import DatabaseError, connection, connections, transaction
    from django.db.models import QuerySet

    if not connection.features.has_select_for_update_nowait:
        pytest.skip('Requires a database with nonblocking row locks, such as PostgreSQL.')
    role = Group.objects.create(name='Locked grants')
    profile = GroupProfile.objects.create(group=role, grants_staff=True, grants_superuser=True)
    user = TrustpointUser(username='locked-grants', role=role)
    if not creating:
        user.save()
    original_first = QuerySet.first

    def row_is_locked():
        model, row_pk = (GroupProfile, profile.pk) if creating else (TrustpointUser, user.pk)
        try:
            with transaction.atomic():
                model.objects.select_for_update(nowait=True).get(pk=row_pk)
        except DatabaseError:
            return True
        finally:
            connections.close_all()
        return False

    def check_after_read(queryset):
        result = original_first(queryset)
        if queryset.model is GroupProfile:
            with ThreadPoolExecutor(max_workers=1) as pool:
                assert pool.submit(row_is_locked).result(timeout=10)
        return result

    with patch.object(QuerySet, 'first', check_after_read):
        user.save()
    assert user.is_staff and user.is_superuser
