"""Tests for TlsViewSet API endpoints."""

from __future__ import annotations

import pytest
from django.contrib.auth import get_user_model
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APIClient

from management.models import KeyStorageConfig
from pki.models import CredentialModel


@pytest.fixture
def api_client() -> APIClient:
    """Return an unauthenticated API client."""
    return APIClient()


@pytest.fixture
def user():
    """Create a test user."""
    User = get_user_model()
    return User.objects.create_user(username='tls_testuser', password='testpass123')


@pytest.fixture
def authenticated_client(api_client: APIClient, user) -> APIClient:
    """Return an API client authenticated as a regular user."""
    api_client.force_authenticate(user=user)
    return api_client


@pytest.fixture
def tls_credential(issuing_ca_instance) -> CredentialModel:
    """Create a CredentialModel of type TRUSTPOINT_TLS_SERVER using the conftest CA fixture."""
    from pki.util.x509 import CertificateGenerator
    from trustpoint_core.serializer import CredentialSerializer

    ca_cert = issuing_ca_instance['cert']
    ca_key = issuing_ca_instance['priv_key']
    ee_cert, ee_key = CertificateGenerator.create_ee(
        issuer_private_key=ca_key,
        issuer_name=ca_cert.subject,
        subject_name='TLS Test Credential',
        validity_days=365,
    )
    serializer = CredentialSerializer(
        private_key=ee_key,
        certificate=ee_cert,
        additional_certificates=[ca_cert],
    )
    return CredentialModel.save_credential_serializer(
        credential_serializer=serializer,
        credential_type=CredentialModel.CredentialTypeChoice.TRUSTPOINT_TLS_SERVER,
    )


@pytest.fixture
def issued_credential(credential_instance) -> CredentialModel:
    """Return the ISSUED_CREDENTIAL CredentialModel created by the conftest fixture."""
    return credential_instance['credential']


@pytest.mark.django_db
class TestTlsViewSetAuthentication:
    """Verify that unauthenticated requests are rejected."""

    def test_list_requires_authentication(self, api_client: APIClient) -> None:
        """Unauthenticated GET /api/tls/ returns 401."""
        response = api_client.get(reverse('tls-list'))
        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    def test_retrieve_requires_authentication(self, api_client: APIClient, tls_credential: CredentialModel) -> None:
        """Unauthenticated GET /api/tls/{id}/ returns 401."""
        url = reverse('tls-detail', args=[tls_credential.pk])
        response = api_client.get(url)
        assert response.status_code == status.HTTP_401_UNAUTHORIZED


@pytest.mark.django_db
class TestTlsViewSetList:
    """Tests for GET /api/tls/."""

    def test_list_returns_200(self, authenticated_client: APIClient) -> None:
        """Authenticated list request returns 200."""
        response = authenticated_client.get(reverse('tls-list'))
        assert response.status_code == status.HTTP_200_OK

    def test_list_contains_created_credentials(self, authenticated_client: APIClient, tls_credential: CredentialModel) -> None:
        """Credentials present in the DB appear in the list response."""
        response = authenticated_client.get(reverse('tls-list'))
        assert response.status_code == status.HTTP_200_OK
        ids = [item['id'] for item in response.data]
        assert tls_credential.pk in ids

    def test_list_exposes_expected_fields(self, authenticated_client: APIClient, tls_credential: CredentialModel) -> None:
        """Each list item exposes id, credential_type, and created_at."""
        response = authenticated_client.get(reverse('tls-list'))
        assert response.status_code == status.HTTP_200_OK
        assert len(response.data) >= 1
        item = next(d for d in response.data if d['id'] == tls_credential.pk)
        assert 'id' in item
        assert 'credential_type' in item
        assert 'created_at' in item


@pytest.mark.django_db
class TestTlsViewSetRetrieve:
    """Tests for GET /api/tls/{id}/."""

    def test_retrieve_existing_returns_200(self, authenticated_client: APIClient, tls_credential: CredentialModel) -> None:
        """Retrieving an existing credential returns 200 with correct data."""
        url = reverse('tls-detail', args=[tls_credential.pk])
        response = authenticated_client.get(url)
        assert response.status_code == status.HTTP_200_OK
        assert response.data['id'] == tls_credential.pk
        assert response.data['credential_type'] == CredentialModel.CredentialTypeChoice.TRUSTPOINT_TLS_SERVER

    def test_retrieve_missing_returns_404(self, authenticated_client: APIClient) -> None:
        """Retrieving a non-existent id returns 404."""
        url = reverse('tls-detail', args=[99999])
        response = authenticated_client.get(url)
        assert response.status_code == status.HTTP_404_NOT_FOUND


@pytest.mark.django_db
class TestTlsViewSetFilter:
    """Tests for GET /api/tls/?credential_type=<type>."""

    def test_filter_by_credential_type_returns_only_matching(
        self,
        authenticated_client: APIClient,
        tls_credential: CredentialModel,
        issued_credential: CredentialModel,
    ) -> None:
        """Filtering by credential_type returns only credentials of that type."""
        url = reverse('tls-list') + f'?credential_type={CredentialModel.CredentialTypeChoice.TRUSTPOINT_TLS_SERVER}'
        response = authenticated_client.get(url)
        assert response.status_code == status.HTTP_200_OK
        returned_ids = {item['id'] for item in response.data}
        assert tls_credential.pk in returned_ids
        assert issued_credential.pk not in returned_ids

    def test_filter_excludes_non_matching_type(
        self,
        authenticated_client: APIClient,
        tls_credential: CredentialModel,
        issued_credential: CredentialModel,
    ) -> None:
        """Filtering by ISSUED_CREDENTIAL type excludes TLS credentials."""
        url = reverse('tls-list') + f'?credential_type={CredentialModel.CredentialTypeChoice.ISSUED_CREDENTIAL}'
        response = authenticated_client.get(url)
        assert response.status_code == status.HTTP_200_OK
        returned_ids = {item['id'] for item in response.data}
        assert issued_credential.pk in returned_ids
        assert tls_credential.pk not in returned_ids


@pytest.mark.django_db
class TestTlsViewSetDelete:
    """Tests for DELETE /api/tls/{id}/."""

    def test_delete_existing_returns_204(self, authenticated_client: APIClient, tls_credential: CredentialModel) -> None:
        """Deleting an existing credential returns 204."""
        url = reverse('tls-detail', args=[tls_credential.pk])
        response = authenticated_client.delete(url)
        assert response.status_code == status.HTTP_204_NO_CONTENT

    def test_delete_removes_credential_from_database(self, authenticated_client: APIClient, tls_credential: CredentialModel) -> None:
        """After DELETE the credential no longer exists in the database."""
        pk = tls_credential.pk
        url = reverse('tls-detail', args=[pk])
        authenticated_client.delete(url)
        assert not CredentialModel.objects.filter(pk=pk).exists()

    def test_delete_missing_returns_404(self, authenticated_client: APIClient) -> None:
        """Deleting a non-existent id returns 404."""
        url = reverse('tls-detail', args=[99999])
        response = authenticated_client.delete(url)
        assert response.status_code == status.HTTP_404_NOT_FOUND
