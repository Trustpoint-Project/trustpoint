"""Tests for BackupViewSet API endpoints."""

from __future__ import annotations

import pytest
from django.contrib.auth import get_user_model
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APIClient

from management.models import BackupOptions, KeyStorageConfig


@pytest.fixture
def api_client() -> APIClient:
    """Return an unauthenticated API client."""
    return APIClient()


@pytest.fixture
def user():
    """Create a test user."""
    User = get_user_model()
    return User.objects.create_user(username='api_testuser', password='testpass123')


@pytest.fixture
def authenticated_client(api_client: APIClient, user) -> APIClient:
    """Return an API client authenticated as a regular user."""
    api_client.force_authenticate(user=user)
    return api_client


@pytest.fixture
def key_storage() -> KeyStorageConfig:
    """Ensure KeyStorageConfig exists (required for models with encrypted fields)."""
    return KeyStorageConfig.get_or_create_default()


@pytest.fixture
def backup_options(key_storage: KeyStorageConfig) -> BackupOptions:
    """Create a BackupOptions instance for use in tests."""
    return BackupOptions.objects.create(remote_directory='/backups/test')


@pytest.mark.django_db
class TestBackupViewSetAuthentication:
    """Verify that unauthenticated requests are rejected."""

    def test_list_requires_authentication(self, api_client: APIClient) -> None:
        """Unauthenticated GET /api/backups/ returns 401."""
        response = api_client.get(reverse('backup-list'))
        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    def test_retrieve_requires_authentication(self, api_client: APIClient, backup_options: BackupOptions) -> None:
        """Unauthenticated GET /api/backups/{id}/ returns 401."""
        url = reverse('backup-detail', args=[backup_options.pk])
        response = api_client.get(url)
        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    def test_delete_requires_authentication(self, api_client: APIClient, backup_options: BackupOptions) -> None:
        """Unauthenticated DELETE /api/backups/{id}/ returns 401."""
        url = reverse('backup-detail', args=[backup_options.pk])
        response = api_client.delete(url)
        assert response.status_code == status.HTTP_401_UNAUTHORIZED


@pytest.mark.django_db
class TestBackupViewSetList:
    """Tests for GET /api/backups/."""

    def test_list_returns_200(self, authenticated_client: APIClient) -> None:
        """Authenticated list request returns 200."""
        response = authenticated_client.get(reverse('backup-list'))
        assert response.status_code == status.HTTP_200_OK

    def test_list_count_matches_database(self, authenticated_client: APIClient, backup_options: BackupOptions) -> None:
        """Response count equals the number of BackupOptions rows in the DB."""
        db_count = BackupOptions.objects.count()
        response = authenticated_client.get(reverse('backup-list'))
        assert response.status_code == status.HTTP_200_OK
        assert len(response.data) == db_count

    def test_list_exposes_expected_fields(self, authenticated_client: APIClient, backup_options: BackupOptions) -> None:
        """Each list item contains the 'id' and 'remote_directory' fields."""
        response = authenticated_client.get(reverse('backup-list'))
        assert response.status_code == status.HTTP_200_OK
        assert len(response.data) >= 1
        first = response.data[0]
        assert 'id' in first
        assert 'remote_directory' in first


@pytest.mark.django_db
class TestBackupViewSetRetrieve:
    """Tests for GET /api/backups/{id}/."""

    def test_retrieve_existing_returns_200(self, authenticated_client: APIClient, backup_options: BackupOptions) -> None:
        """Retrieving an existing BackupOptions returns 200 with correct data."""
        url = reverse('backup-detail', args=[backup_options.pk])
        response = authenticated_client.get(url)
        assert response.status_code == status.HTTP_200_OK
        assert response.data['id'] == backup_options.pk
        assert response.data['remote_directory'] == '/backups/test'

    def test_retrieve_missing_returns_404(self, authenticated_client: APIClient) -> None:
        """Retrieving a non-existent id returns 404."""
        url = reverse('backup-detail', args=[99999])
        response = authenticated_client.get(url)
        assert response.status_code == status.HTTP_404_NOT_FOUND


@pytest.mark.django_db
class TestBackupViewSetCreate:
    """Tests for POST /api/backups/."""

    def test_create_with_valid_data_returns_201(self, authenticated_client: APIClient, key_storage: KeyStorageConfig) -> None:
        """Valid POST creates a BackupOptions row and returns 201."""
        payload = {'remote_directory': '/var/backups/new'}
        response = authenticated_client.post(reverse('backup-list'), payload, format='json')
        assert response.status_code == status.HTTP_201_CREATED
        assert BackupOptions.objects.filter(remote_directory='/var/backups/new').exists()

    def test_create_returns_id_in_response(self, authenticated_client: APIClient, key_storage: KeyStorageConfig) -> None:
        """Created response body contains the new object's id."""
        payload = {'remote_directory': '/var/backups/with-id'}
        response = authenticated_client.post(reverse('backup-list'), payload, format='json')
        assert response.status_code == status.HTTP_201_CREATED
        assert 'id' in response.data


@pytest.mark.django_db
class TestBackupViewSetDelete:
    """Tests for DELETE /api/backups/{id}/."""

    def test_delete_existing_returns_204(self, authenticated_client: APIClient, backup_options: BackupOptions) -> None:
        """Deleting an existing BackupOptions returns 204."""
        url = reverse('backup-detail', args=[backup_options.pk])
        response = authenticated_client.delete(url)
        assert response.status_code == status.HTTP_204_NO_CONTENT

    def test_delete_removes_row_from_database(self, authenticated_client: APIClient, backup_options: BackupOptions) -> None:
        """After DELETE the row is gone from the database."""
        pk = backup_options.pk
        url = reverse('backup-detail', args=[pk])
        authenticated_client.delete(url)
        assert not BackupOptions.objects.filter(pk=pk).exists()

    def test_delete_missing_returns_404(self, authenticated_client: APIClient) -> None:
        """Deleting a non-existent id returns 404."""
        url = reverse('backup-detail', args=[99999])
        response = authenticated_client.delete(url)
        assert response.status_code == status.HTTP_404_NOT_FOUND
