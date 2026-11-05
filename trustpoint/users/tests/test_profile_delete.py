# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Tests for owner- and manager-initiated profile deletion."""

from collections.abc import Iterator
from contextlib import ExitStack
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from django.contrib.auth.models import Group, Permission
from django.test import Client
from django.urls import reverse

from users.models import BuiltinRole, TrustpointUser

HTTP_OK = 200
HTTP_REDIRECT = 302
HTTP_FORBIDDEN = 403


@pytest.fixture(autouse=True)
def bypass_unmigrated_policy_reads() -> Iterator[None]:
    """Isolate delete-view tests from password-policy columns missing in the local database."""
    with ExitStack() as stack:
        stack.enter_context(patch('users.middleware.TrustpointUser.password_is_expired', return_value=False))
        stack.enter_context(patch('users.middleware.PasswordPolicy.is_otp_required', return_value=False))
        stack.enter_context(
            patch(
                'users.middleware.AccountSecurityConfig.get',
                return_value=SimpleNamespace(idle_timeout_minutes=30),
            ),
        )
        yield


@pytest.mark.django_db
def test_owner_can_confirm_self_deletion(client: Client) -> None:
    """Delete the signed-in account only after confirmation and end its session."""
    user = TrustpointUser.objects.create_user(username='owner')
    client.force_login(user)
    profile_response = client.get(reverse('users:profile'))
    assert profile_response.status_code == HTTP_OK
    assert b'Delete Account' in profile_response.content
    assert reverse('users:profile_delete').encode() in profile_response.content
    delete_url = reverse('users:profile_delete')

    response = client.get(delete_url)

    assert response.status_code == HTTP_OK
    assert 'permanently delete your account' in response.content.decode()

    response = client.post(delete_url)

    assert response.status_code == HTTP_REDIRECT
    assert response.url == reverse('users:login')
    assert not TrustpointUser.objects.filter(pk=user.pk).exists()
    assert '_auth_user_id' not in client.session


@pytest.mark.django_db
def test_user_manager_can_delete_another_human_user(client: Client) -> None:
    """Allow a user manager to delete another human account after confirmation."""
    manager = TrustpointUser.objects.create_user(username='manager')
    target = TrustpointUser.objects.create_user(username='target')
    permission = Permission.objects.get(codename='manage_users')
    manager.user_permissions.add(permission)
    client.force_login(manager)
    profile_response = client.get(reverse('users:user-profile', kwargs={'pk': target.pk}))
    assert profile_response.status_code == HTTP_OK
    assert b'Delete Account' in profile_response.content
    assert reverse('users:user-profile-delete', kwargs={'pk': target.pk}).encode() in profile_response.content
    delete_url = reverse('users:user-profile-delete', kwargs={'pk': target.pk})

    response = client.get(delete_url)

    assert response.status_code == HTTP_OK
    assert target.username in response.content.decode()

    response = client.post(delete_url)

    assert response.status_code == HTTP_REDIRECT
    assert response.url == reverse('users:profile')
    assert not TrustpointUser.objects.filter(pk=target.pk).exists()
    assert TrustpointUser.objects.filter(pk=manager.pk).exists()


@pytest.mark.django_db
def test_non_manager_cannot_delete_another_user(client: Client) -> None:
    """Deny deletion of another user's account without manage-users permission."""
    requester = TrustpointUser.objects.create_user(username='requester')
    target = TrustpointUser.objects.create_user(username='target')
    client.force_login(requester)

    response = client.get(reverse('users:user-profile-delete', kwargs={'pk': target.pk}))

    assert response.status_code == HTTP_FORBIDDEN
    assert TrustpointUser.objects.filter(pk=target.pk).exists()


@pytest.mark.django_db
def test_final_admin_cannot_delete_their_own_account(client: Client) -> None:
    """Keep the last administrator safeguard active for self-deletion."""
    admin_role, _ = Group.objects.get_or_create(name=BuiltinRole.ADMIN.value)
    admin = TrustpointUser.objects.create_user(username='admin', role=admin_role)
    admin.user_permissions.add(Permission.objects.get(codename='manage_users'))
    client.force_login(admin)

    response = client.post(reverse('users:profile_delete'))

    assert response.status_code == HTTP_REDIRECT
    assert response.url == reverse('users:profile')
    assert TrustpointUser.objects.filter(pk=admin.pk).exists()
