"""Tests for DeviceViewSet API endpoints.

DeviceViewSet is a standard ModelViewSet registered at /api/devices/.
All endpoints require authentication (global IsAuthenticated permission).
The serializer uses fields='__all__', so all model fields appear in responses.
"""

from __future__ import annotations

import pytest
from django.contrib.auth import get_user_model
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APIClient

from django.contrib.auth.base_user import AbstractBaseUser

from devices.models import DeviceModel
from management.models import KeyStorageConfig
from onboarding.models import NoOnboardingConfigModel, NoOnboardingPkiProtocol


@pytest.fixture
def api_client() -> APIClient:
    """Return an unauthenticated API client."""
    return APIClient()


@pytest.fixture
def user() -> AbstractBaseUser:
    """Create a test user."""
    User = get_user_model()
    return User.objects.create_user(username='device_api_testuser', password='testpass123')


@pytest.fixture
def authenticated_client(api_client: APIClient, user: AbstractBaseUser) -> APIClient:
    """Return an API client authenticated as a regular user."""
    api_client.force_authenticate(user=user)
    return api_client


@pytest.fixture
def no_onboarding_config() -> NoOnboardingConfigModel:
    """Create a minimal NoOnboardingConfigModel with MANUAL protocol."""
    KeyStorageConfig.get_or_create_default()
    config = NoOnboardingConfigModel()
    config.set_pki_protocols([NoOnboardingPkiProtocol.MANUAL])
    config.full_clean()
    config.save()
    return config


@pytest.fixture
def device(no_onboarding_config: NoOnboardingConfigModel) -> DeviceModel:
    """Create a DeviceModel without domain for API testing."""
    return DeviceModel.objects.create(
        common_name='api-test-device',
        serial_number='SN-API-001',
        no_onboarding_config=no_onboarding_config,
    )


@pytest.mark.django_db
class TestDeviceViewSetAuthentication:
    """Verify that unauthenticated requests are rejected."""

    def test_list_requires_authentication(self, api_client: APIClient) -> None:
        """Unauthenticated GET /api/devices/ returns 401."""
        response = api_client.get(reverse('device-list'))
        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    def test_retrieve_requires_authentication(self, api_client: APIClient, device: DeviceModel) -> None:
        """Unauthenticated GET /api/devices/{id}/ returns 401."""
        response = api_client.get(reverse('device-detail', args=[device.pk]))
        assert response.status_code == status.HTTP_401_UNAUTHORIZED


@pytest.mark.django_db
class TestDeviceViewSetList:
    """Tests for GET /api/devices/."""

    def test_list_returns_200(self, authenticated_client: APIClient) -> None:
        """Authenticated list request returns 200."""
        response = authenticated_client.get(reverse('device-list'))
        assert response.status_code == status.HTTP_200_OK

    def test_list_contains_created_device(self, authenticated_client: APIClient, device: DeviceModel) -> None:
        """Devices present in the DB appear in the list response."""
        response = authenticated_client.get(reverse('device-list'))
        assert response.status_code == status.HTTP_200_OK
        ids = [item['id'] for item in response.data]
        assert device.pk in ids

    def test_list_exposes_expected_fields(self, authenticated_client: APIClient, device: DeviceModel) -> None:
        """Each list item includes core device fields."""
        response = authenticated_client.get(reverse('device-list'))
        assert response.status_code == status.HTTP_200_OK
        item = next(d for d in response.data if d['id'] == device.pk)
        for field in ('id', 'common_name', 'serial_number', 'device_type', 'created_at', 'rfc_4122_uuid'):
            assert field in item


@pytest.mark.django_db
class TestDeviceViewSetRetrieve:
    """Tests for GET /api/devices/{id}/."""

    def test_retrieve_existing_returns_200(self, authenticated_client: APIClient, device: DeviceModel) -> None:
        """Retrieving an existing device returns 200 with correct data."""
        response = authenticated_client.get(reverse('device-detail', args=[device.pk]))
        assert response.status_code == status.HTTP_200_OK
        assert response.data['id'] == device.pk
        assert response.data['common_name'] == 'api-test-device'
        assert response.data['serial_number'] == 'SN-API-001'

    def test_retrieve_returns_uuid(self, authenticated_client: APIClient, device: DeviceModel) -> None:
        """Retrieved device includes the auto-generated rfc_4122_uuid field."""
        response = authenticated_client.get(reverse('device-detail', args=[device.pk]))
        assert response.status_code == status.HTTP_200_OK
        assert response.data['rfc_4122_uuid'] == str(device.rfc_4122_uuid)

    def test_retrieve_missing_returns_404(self, authenticated_client: APIClient) -> None:
        """Retrieving a non-existent id returns 404."""
        response = authenticated_client.get(reverse('device-detail', args=[99999]))
        assert response.status_code == status.HTTP_404_NOT_FOUND


@pytest.mark.django_db
class TestDeviceViewSetCreate:
    """Tests for POST /api/devices/."""

    def test_create_with_valid_data_returns_201(
        self, authenticated_client: APIClient, no_onboarding_config: NoOnboardingConfigModel
    ) -> None:
        """Valid POST creates a device and returns 201."""
        payload = {
            'common_name': 'new-api-device',
            'no_onboarding_config': no_onboarding_config.pk,
        }
        response = authenticated_client.post(reverse('device-list'), payload, format='json')
        assert response.status_code == status.HTTP_201_CREATED

    def test_create_device_exists_in_database(
        self, authenticated_client: APIClient, no_onboarding_config: NoOnboardingConfigModel
    ) -> None:
        """After successful POST the device exists in the database."""
        payload = {
            'common_name': 'db-check-device',
            'no_onboarding_config': no_onboarding_config.pk,
        }
        authenticated_client.post(reverse('device-list'), payload, format='json')
        assert DeviceModel.objects.filter(common_name='db-check-device').exists()

    def test_create_response_contains_id_and_uuid(
        self, authenticated_client: APIClient, no_onboarding_config: NoOnboardingConfigModel
    ) -> None:
        """Created response body includes id and the auto-generated rfc_4122_uuid."""
        payload = {
            'common_name': 'uuid-test-device',
            'no_onboarding_config': no_onboarding_config.pk,
        }
        response = authenticated_client.post(reverse('device-list'), payload, format='json')
        assert response.status_code == status.HTTP_201_CREATED
        assert 'id' in response.data
        assert response.data['rfc_4122_uuid'] is not None

    def test_create_invalid_device_type_returns_400(
        self, authenticated_client: APIClient, no_onboarding_config: NoOnboardingConfigModel
    ) -> None:
        """POST with an invalid device_type choice returns 400."""
        payload = {
            'common_name': 'invalid-type-device',
            'no_onboarding_config': no_onboarding_config.pk,
            'device_type': 999,
        }
        response = authenticated_client.post(reverse('device-list'), payload, format='json')
        assert response.status_code == status.HTTP_400_BAD_REQUEST

    def test_create_duplicate_common_name_returns_400(
        self,
        authenticated_client: APIClient,
        device: DeviceModel,
        no_onboarding_config: NoOnboardingConfigModel,
    ) -> None:
        """POST with a common_name that already exists returns 400 (unique constraint)."""
        payload = {
            'common_name': device.common_name,
            'no_onboarding_config': no_onboarding_config.pk,
        }
        response = authenticated_client.post(reverse('device-list'), payload, format='json')
        assert response.status_code == status.HTTP_400_BAD_REQUEST


@pytest.mark.django_db
class TestDeviceViewSetUpdate:
    """Tests for PATCH /api/devices/{id}/."""

    def test_patch_updates_field(self, authenticated_client: APIClient, device: DeviceModel) -> None:
        """PATCH with a new serial_number updates the device and returns 200."""
        url = reverse('device-detail', args=[device.pk])
        response = authenticated_client.patch(url, {'serial_number': 'SN-UPDATED'}, format='json')
        assert response.status_code == status.HTTP_200_OK
        assert response.data['serial_number'] == 'SN-UPDATED'
        device.refresh_from_db()
        assert device.serial_number == 'SN-UPDATED'

    def test_patch_missing_device_returns_404(self, authenticated_client: APIClient) -> None:
        """PATCH on a non-existent device returns 404."""
        response = authenticated_client.patch(
            reverse('device-detail', args=[99999]), {'serial_number': 'X'}, format='json'
        )
        assert response.status_code == status.HTTP_404_NOT_FOUND


@pytest.mark.django_db
class TestDeviceViewSetDelete:
    """Tests for DELETE /api/devices/{id}/."""

    def test_delete_existing_returns_204(self, authenticated_client: APIClient, device: DeviceModel) -> None:
        """Deleting an existing device returns 204."""
        response = authenticated_client.delete(reverse('device-detail', args=[device.pk]))
        assert response.status_code == status.HTTP_204_NO_CONTENT

    def test_delete_removes_device_from_database(self, authenticated_client: APIClient, device: DeviceModel) -> None:
        """After DELETE the device no longer exists in the database."""
        pk = device.pk
        authenticated_client.delete(reverse('device-detail', args=[pk]))
        assert not DeviceModel.objects.filter(pk=pk).exists()

    def test_delete_missing_returns_404(self, authenticated_client: APIClient) -> None:
        """Deleting a non-existent id returns 404."""
        response = authenticated_client.delete(reverse('device-detail', args=[99999]))
        assert response.status_code == status.HTTP_404_NOT_FOUND
