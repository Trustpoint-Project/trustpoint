"""Tests for UserViewSet API endpoints."""

from __future__ import annotations

import pytest
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APIClient

from users.models import GroupProfile

User = get_user_model()


def _create_admin_group() -> Group:
    group, _ = Group.objects.get_or_create(name='Admin')
    GroupProfile.objects.get_or_create(group=group, defaults={'grants_staff': True, 'grants_superuser': True})
    return group


def _create_plain_group(name: str = 'Viewer') -> Group:
    group, _ = Group.objects.get_or_create(name=name)
    GroupProfile.objects.get_or_create(group=group, defaults={'grants_staff': False, 'grants_superuser': False})
    return group


@pytest.fixture
def api_client() -> APIClient:
    """Return an unauthenticated API client."""
    return APIClient()


@pytest.fixture
def admin_group() -> Group:
    """Return the built-in Admin group."""
    return _create_admin_group()


@pytest.fixture
def plain_group() -> Group:
    """Return a non-admin role."""
    return _create_plain_group()


@pytest.fixture
def superuser(admin_group: Group):
    """Create a superuser assigned to the Admin role."""
    return User.objects.create_user(username='api_admin', password='AdminPass123!', role=admin_group)  # noqa: S106


@pytest.fixture
def regular_user(plain_group: Group):
    """Create a non-superuser assigned to a plain role."""
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
class TestUserViewSetAuthentication:
    """Verify that unauthenticated requests are rejected."""

    def test_list_requires_authentication(self, api_client: APIClient) -> None:
        """Unauthenticated GET /api/users/ returns 401."""
        response = api_client.get(reverse('users-list'))
        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    def test_create_requires_authentication(self, api_client: APIClient) -> None:
        """Unauthenticated POST /api/users/ returns 401."""
        response = api_client.post(reverse('users-list'), {'username': 'x'}, format='json')
        assert response.status_code == status.HTTP_401_UNAUTHORIZED


@pytest.mark.django_db
class TestUserViewSetAuthorization:
    """Verify that only superusers may use this API."""

    def test_non_superuser_list_returns_403(self, regular_client: APIClient) -> None:
        """A non-superuser cannot list users."""
        response = regular_client.get(reverse('users-list'))
        assert response.status_code == status.HTTP_403_FORBIDDEN

    def test_non_superuser_retrieve_own_record_returns_403(self, regular_client: APIClient, regular_user) -> None:
        """A non-superuser cannot even retrieve their own record via this API."""
        url = reverse('users-detail', args=[regular_user.pk])
        response = regular_client.get(url)
        assert response.status_code == status.HTTP_403_FORBIDDEN

    def test_non_superuser_create_returns_403(self, regular_client: APIClient) -> None:
        """A non-superuser cannot create users."""
        response = regular_client.post(reverse('users-list'), {'username': 'x'}, format='json')
        assert response.status_code == status.HTTP_403_FORBIDDEN


@pytest.mark.django_db
class TestUserViewSetCreate:
    """Tests for POST /api/users/."""

    def test_create_with_valid_data_returns_201(self, superuser_client: APIClient, plain_group: Group) -> None:
        """Valid POST creates a user and returns 201."""
        payload = {'username': 'newuser', 'password': 'StrongPass123!', 'role': plain_group.pk}
        response = superuser_client.post(reverse('users-list'), payload, format='json')
        assert response.status_code == status.HTTP_201_CREATED, response.data
        assert User.objects.filter(username='newuser').exists()

    def test_create_response_never_contains_password(self, superuser_client: APIClient, plain_group: Group) -> None:
        """The response body never echoes the password back."""
        payload = {'username': 'newuser2', 'password': 'StrongPass123!', 'role': plain_group.pk}
        response = superuser_client.post(reverse('users-list'), payload, format='json')
        assert response.status_code == status.HTTP_201_CREATED, response.data
        assert 'password' not in response.data

    def test_create_without_password_returns_400(self, superuser_client: APIClient, plain_group: Group) -> None:
        """Creating a user without a password is rejected."""
        payload = {'username': 'nopassword', 'role': plain_group.pk}
        response = superuser_client.post(reverse('users-list'), payload, format='json')
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert not User.objects.filter(username='nopassword').exists()

    def test_create_with_weak_password_returns_400(self, superuser_client: APIClient, plain_group: Group) -> None:
        """Creating a user with a weak password is rejected by AUTH_PASSWORD_VALIDATORS."""
        payload = {'username': 'weakpass', 'password': '123', 'role': plain_group.pk}
        response = superuser_client.post(reverse('users-list'), payload, format='json')
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert not User.objects.filter(username='weakpass').exists()


@pytest.mark.django_db
class TestUserViewSetUpdate:
    """Tests for PATCH /api/users/{id}/."""

    def test_update_role_success(
        self, superuser_client: APIClient, regular_user, admin_group: Group,
    ) -> None:
        """A superuser can change another user's role."""
        url = reverse('users-detail', args=[regular_user.pk])
        response = superuser_client.patch(url, {'role': admin_group.pk}, format='json')
        assert response.status_code == status.HTTP_200_OK, response.data
        regular_user.refresh_from_db()
        assert regular_user.role_id == admin_group.pk
        assert regular_user.is_superuser is True

    def test_downgrade_last_admin_is_blocked(
        self, superuser_client: APIClient, superuser, plain_group: Group,
    ) -> None:
        """Changing the sole admin's role away from Admin is rejected."""
        url = reverse('users-detail', args=[superuser.pk])
        response = superuser_client.patch(url, {'role': plain_group.pk}, format='json')
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        superuser.refresh_from_db()
        assert superuser.is_superuser is True


@pytest.mark.django_db
class TestUserViewSetDelete:
    """Tests for DELETE /api/users/{id}/."""

    def test_delete_non_admin_returns_204(self, superuser_client: APIClient, regular_user) -> None:
        """Deleting a non-admin user succeeds."""
        url = reverse('users-detail', args=[regular_user.pk])
        response = superuser_client.delete(url)
        assert response.status_code == status.HTTP_204_NO_CONTENT
        assert not User.objects.filter(pk=regular_user.pk).exists()

    def test_delete_last_admin_is_blocked(self, superuser_client: APIClient, superuser) -> None:
        """Deleting the sole remaining admin is rejected."""
        url = reverse('users-detail', args=[superuser.pk])
        response = superuser_client.delete(url)
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert User.objects.filter(pk=superuser.pk).exists()
