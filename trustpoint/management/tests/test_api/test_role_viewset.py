# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Tests for RoleViewSet API endpoints."""

from __future__ import annotations

import pytest
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group, Permission
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APIClient

from users.models import GroupProfile

User = get_user_model()


def _create_admin_group() -> Group:
    group, _ = Group.objects.get_or_create(name='Admin')
    GroupProfile.objects.get_or_create(group=group, defaults={'grants_staff': True, 'grants_superuser': True})
    return group


@pytest.fixture
def api_client() -> APIClient:
    """Return an unauthenticated API client."""
    return APIClient()


@pytest.fixture
def admin_group() -> Group:
    """Return the built-in, protected Admin group."""
    return _create_admin_group()


@pytest.fixture
def superuser(admin_group: Group):
    """Create a superuser assigned to the Admin role."""
    return User.objects.create_user(username='api_admin', password='AdminPass123!', role=admin_group)  # noqa: S106


@pytest.fixture
def regular_user():
    """Create a non-superuser assigned to a plain role."""
    plain_group, _ = Group.objects.get_or_create(name='Viewer')
    GroupProfile.objects.get_or_create(group=plain_group, defaults={'grants_staff': False, 'grants_superuser': False})
    return User.objects.create_user(username='api_regular', password='RegularPass123!', role=plain_group)  # noqa: S106


@pytest.fixture
def superuser_client(api_client: APIClient, superuser) -> APIClient:
    """Return an API client authenticated as a superuser."""
    api_client.force_authenticate(user=superuser)
    return api_client


@pytest.fixture
def regular_client(api_client: APIClient, regular_user) -> APIClient:
    """Return an API client authenticated as a non-superuser."""
    api_client.force_authenticate(user=regular_user)
    return api_client


@pytest.mark.django_db
class TestRoleViewSetAuthentication:
    """Verify that unauthenticated requests are rejected."""

    def test_list_requires_authentication(self, api_client: APIClient) -> None:
        """Unauthenticated GET /api/roles/ returns 401."""
        response = api_client.get(reverse('roles-list'))
        assert response.status_code == status.HTTP_401_UNAUTHORIZED


@pytest.mark.django_db
class TestRoleViewSetAuthorization:
    """Verify that only superusers may use this API."""

    def test_non_superuser_list_returns_403(self, regular_client: APIClient) -> None:
        """A non-superuser cannot list roles."""
        response = regular_client.get(reverse('roles-list'))
        assert response.status_code == status.HTTP_403_FORBIDDEN

    def test_non_superuser_create_returns_403(self, regular_client: APIClient) -> None:
        """A non-superuser cannot create roles."""
        response = regular_client.post(reverse('roles-list'), {'name': 'x'}, format='json')
        assert response.status_code == status.HTTP_403_FORBIDDEN


@pytest.mark.django_db
class TestRoleViewSetAvailablePermissions:
    """Tests for GET /api/roles/available-permissions/."""

    def test_returns_the_four_app_permissions(self, superuser_client: APIClient) -> None:
        """Returns exactly the AppPermission-scoped permissions with id and name."""
        response = superuser_client.get(reverse('roles-available-permissions'))
        assert response.status_code == status.HTTP_200_OK, response.data
        expected = set(Permission.objects.filter(content_type__model='apppermission').values_list('id', flat=True))
        assert {item['id'] for item in response.data} == expected
        for item in response.data:
            assert 'name' in item


@pytest.mark.django_db
class TestRoleViewSetCreate:
    """Tests for POST /api/roles/."""

    def test_create_with_permissions_success(self, superuser_client: APIClient) -> None:
        """Valid POST creates the role, its GroupProfile, and assigns the given permissions."""
        perm_id = Permission.objects.filter(content_type__model='apppermission').first().pk
        payload = {'name': 'Operator', 'permissions': [perm_id], 'grants_staff': True}
        response = superuser_client.post(reverse('roles-list'), payload, format='json')
        assert response.status_code == status.HTTP_201_CREATED, response.data
        group = Group.objects.get(name='Operator')
        assert list(group.permissions.values_list('id', flat=True)) == [perm_id]
        assert GroupProfile.objects.get(group=group).grants_staff is True

    def test_create_response_includes_computed_fields(self, superuser_client: APIClient) -> None:
        """The response includes is_protected and user_count for a freshly created role."""
        response = superuser_client.post(reverse('roles-list'), {'name': 'Auditor'}, format='json')
        assert response.status_code == status.HTTP_201_CREATED, response.data
        assert response.data['is_protected'] is False
        assert response.data['user_count'] == 0


@pytest.mark.django_db
class TestRoleViewSetUpdate:
    """Tests for PATCH /api/roles/{id}/."""

    def test_update_grants_superuser_success(self, superuser_client: APIClient) -> None:
        """A superuser can update a role's grants_superuser flag."""
        group, _ = Group.objects.get_or_create(name='Custom')
        GroupProfile.objects.get_or_create(group=group, defaults={'grants_staff': False, 'grants_superuser': False})
        url = reverse('roles-detail', args=[group.pk])
        response = superuser_client.patch(url, {'grants_superuser': True}, format='json')
        assert response.status_code == status.HTTP_200_OK, response.data
        assert GroupProfile.objects.get(group=group).grants_superuser is True

    def test_rename_admin_role_is_blocked(self, superuser_client: APIClient, admin_group: Group) -> None:
        """Renaming the protected Admin role is rejected."""
        url = reverse('roles-detail', args=[admin_group.pk])
        response = superuser_client.patch(url, {'name': 'NotAdmin'}, format='json')
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        admin_group.refresh_from_db()
        assert admin_group.name == 'Admin'

    def test_updating_admin_role_permissions_without_renaming_is_allowed(
        self,
        superuser_client: APIClient,
        admin_group: Group,
    ) -> None:
        """Non-rename updates to the Admin role (e.g. permissions) are still allowed."""
        perm_id = Permission.objects.filter(content_type__model='apppermission').first().pk
        url = reverse('roles-detail', args=[admin_group.pk])
        response = superuser_client.patch(url, {'permissions': [perm_id]}, format='json')
        assert response.status_code == status.HTTP_200_OK, response.data

    def test_update_with_list_payload_returns_400(self, superuser_client: APIClient) -> None:
        """A non-object JSON payload is rejected instead of raising an application error."""
        group, _ = Group.objects.get_or_create(name='Custom')
        response = superuser_client.patch(reverse('roles-detail', args=[group.pk]), [], format='json')

        assert response.status_code == status.HTTP_400_BAD_REQUEST


@pytest.mark.django_db
class TestRoleViewSetDelete:
    """Tests for DELETE /api/roles/{id}/."""

    def test_delete_unused_role_returns_204(self, superuser_client: APIClient) -> None:
        """Deleting a custom role with no assigned users succeeds."""
        group, _ = Group.objects.get_or_create(name='Temp')
        GroupProfile.objects.get_or_create(group=group, defaults={'grants_staff': False, 'grants_superuser': False})
        url = reverse('roles-detail', args=[group.pk])
        response = superuser_client.delete(url)
        assert response.status_code == status.HTTP_204_NO_CONTENT
        assert not Group.objects.filter(pk=group.pk).exists()

    def test_delete_admin_role_is_blocked(self, superuser_client: APIClient, admin_group: Group) -> None:
        """Deleting the protected Admin role is rejected."""
        url = reverse('roles-detail', args=[admin_group.pk])
        response = superuser_client.delete(url)
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert Group.objects.filter(pk=admin_group.pk).exists()

    def test_delete_role_with_assigned_users_is_blocked(self, superuser_client: APIClient) -> None:
        """Deleting a role that still has users assigned is rejected."""
        group, _ = Group.objects.get_or_create(name='Occupied')
        GroupProfile.objects.get_or_create(group=group, defaults={'grants_staff': False, 'grants_superuser': False})
        User.objects.create_user(username='occupant', password='pass', role=group)  # noqa: S106

        url = reverse('roles-detail', args=[group.pk])
        response = superuser_client.delete(url)
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert Group.objects.filter(pk=group.pk).exists()
