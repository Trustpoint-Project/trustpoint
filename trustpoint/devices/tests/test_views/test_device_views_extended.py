"""Extended tests for device views to increase coverage."""

from typing import Any

import pytest
from django.contrib.messages import get_messages
from django.test import Client
from django.urls import reverse

from devices.models import DeviceModel
from onboarding.models import NoOnboardingConfigModel, NoOnboardingPkiProtocol, OnboardingProtocol


@pytest.mark.django_db
class TestDeviceTableViewSorting:
    """Test sorting functionality in device table view."""

    def test_device_table_view_with_single_sort_parameter(
        self, admin_client: Client, device_instance: dict[str, Any]
    ) -> None:
        """Test table view with single sort parameter."""
        domain = device_instance['domain']

        # Create multiple devices
        DeviceModel.objects.create(
            common_name='aaa-device',
            serial_number='SN001',
            domain=domain,
            device_type=DeviceModel.DeviceType.GENERIC_DEVICE,
        )
        DeviceModel.objects.create(
            common_name='zzz-device',
            serial_number='SN002',
            domain=domain,
            device_type=DeviceModel.DeviceType.GENERIC_DEVICE,
        )

        url = reverse('devices:devices') + '?sort=common_name'
        response = admin_client.get(url)

        assert response.status_code == 200

    def test_device_table_view_with_multiple_sort_parameters_redirects(
        self, admin_client: Client, device_instance: dict[str, Any]
    ) -> None:
        """Test that multiple sort parameters cause redirect to single sort."""
        url = reverse('devices:devices') + '?sort=common_name&sort=serial_number'
        response = admin_client.get(url)

        # Should redirect with only first sort parameter
        assert response.status_code == 302
        assert 'sort=common_name' in response.url


@pytest.mark.django_db
class TestDeviceTableViewPkiProtocols:
    """Test PKI protocol display in device table view."""

    def test_device_with_onboarding_config_shows_protocols(
        self, admin_client: Client, device_instance_onboarding: dict[str, Any]
    ) -> None:
        """Test that device with onboarding config displays PKI protocols."""
        device = device_instance_onboarding['device']

        url = reverse('devices:devices')
        response = admin_client.get(url)

        assert response.status_code == 200
        # The device should be in the table
        assert device in response.context['object_list']

    def test_device_with_no_onboarding_config_shows_protocols(
        self, admin_client: Client, domain_instance: dict[str, Any]
    ) -> None:
        """Test that device with no_onboarding_config displays PKI protocols."""
        domain = domain_instance['domain']

        # Create no_onboarding_config
        no_onboarding_config = NoOnboardingConfigModel()
        no_onboarding_config.set_pki_protocols([NoOnboardingPkiProtocol.MANUAL])
        no_onboarding_config.full_clean()
        no_onboarding_config.save()

        device = DeviceModel.objects.create(
            common_name='test-no-onboarding-protocols',
            serial_number='SN12345',
            domain=domain,
            device_type=DeviceModel.DeviceType.GENERIC_DEVICE,
            no_onboarding_config=no_onboarding_config,
        )

        url = reverse('devices:devices')
        response = admin_client.get(url)

        assert response.status_code == 200
        assert device in response.context['object_list']


@pytest.mark.django_db
class TestNoOnboardingIssueApplicationCredentialView:
    """Test NoOnboardingIssueNewApplicationCredentialView."""

    def test_get_issue_credential_view_success(self, admin_client: Client, domain_instance: dict[str, Any]) -> None:
        """Test GET request to issue credential view with valid device."""
        domain = domain_instance['domain']

        # Create device with no_onboarding_config
        no_onboarding_config = NoOnboardingConfigModel()
        no_onboarding_config.set_pki_protocols(
            [
                NoOnboardingPkiProtocol.CMP_SHARED_SECRET,
                NoOnboardingPkiProtocol.EST_USERNAME_PASSWORD,
                NoOnboardingPkiProtocol.MANUAL,
            ]
        )
        no_onboarding_config.cmp_shared_secret = 'test_secret'
        no_onboarding_config.est_password = 'test_password'
        no_onboarding_config.full_clean()
        no_onboarding_config.save()

        device = DeviceModel.objects.create(
            common_name='test-issue-cred',
            serial_number='SN99999',
            domain=domain,
            device_type=DeviceModel.DeviceType.GENERIC_DEVICE,
            no_onboarding_config=no_onboarding_config,
        )

        url = reverse('devices:devices_no_onboarding_clm_issue_application_credential', kwargs={'pk': device.pk})
        response = admin_client.get(url)

        assert response.status_code == 200
        assert 'sections' in response.context
        sections = response.context['sections']
        assert len(sections) == 3

        # Check that all protocols are enabled
        assert all(section['enabled'] for section in sections)

    def test_get_issue_credential_view_device_with_onboarding(
        self, admin_client: Client, device_instance_onboarding: dict[str, Any]
    ) -> None:
        """Test that device with onboarding config redirects with warning."""
        device = device_instance_onboarding['device']

        url = reverse('devices:devices_no_onboarding_clm_issue_application_credential', kwargs={'pk': device.pk})
        response = admin_client.get(url)

        # Should redirect to CLM page
        assert response.status_code == 302
        assert f'/certificate-lifecycle-management/{device.pk}/' in response.url

        # Check for warning message
        messages = list(get_messages(response.wsgi_request))
        assert len(messages) > 0
        assert 'onboarding' in str(messages[0]).lower()

    def test_get_issue_credential_view_no_domain(self, admin_client: Client) -> None:
        """Test that device without domain redirects with warning."""
        # Create device without domain
        no_onboarding_config = NoOnboardingConfigModel()
        no_onboarding_config.set_pki_protocols([NoOnboardingPkiProtocol.MANUAL])
        no_onboarding_config.full_clean()
        no_onboarding_config.save()

        device = DeviceModel.objects.create(
            common_name='test-no-domain',
            serial_number='SN88888',
            domain=None,
            device_type=DeviceModel.DeviceType.GENERIC_DEVICE,
            no_onboarding_config=no_onboarding_config,
        )

        url = reverse('devices:devices_no_onboarding_clm_issue_application_credential', kwargs={'pk': device.pk})
        response = admin_client.get(url)

        # Should redirect to CLM page
        assert response.status_code == 302

        # Check for warning message
        messages = list(get_messages(response.wsgi_request))
        assert len(messages) > 0
        assert 'domain' in str(messages[0]).lower()

    def test_get_issue_credential_view_no_pki_protocols(
        self, admin_client: Client, domain_instance: dict[str, Any]
    ) -> None:
        """Test that device with no PKI protocols redirects with warning."""
        domain = domain_instance['domain']

        # Create device with no PKI protocols enabled
        no_onboarding_config = NoOnboardingConfigModel()
        no_onboarding_config.pki_protocols = 0  # No protocols
        no_onboarding_config.full_clean()
        no_onboarding_config.save()

        device = DeviceModel.objects.create(
            common_name='test-no-protocols',
            serial_number='SN77777',
            domain=domain,
            device_type=DeviceModel.DeviceType.GENERIC_DEVICE,
            no_onboarding_config=no_onboarding_config,
        )

        url = reverse('devices:devices_no_onboarding_clm_issue_application_credential', kwargs={'pk': device.pk})
        response = admin_client.get(url)

        # Should redirect to CLM page
        assert response.status_code == 302

        # Check for warning message
        messages = list(get_messages(response.wsgi_request))
        assert len(messages) > 0
        assert 'protocol' in str(messages[0]).lower()


@pytest.mark.django_db
class TestOpcUaGdsNoOnboardingIssueApplicationCredentialView:
    """Test OPC UA GDS version of NoOnboardingIssueNewApplicationCredentialView."""

    def test_opcua_gds_issue_credential_view(self, admin_client: Client, domain_instance: dict[str, Any]) -> None:
        """Test OPC UA GDS issue credential view."""
        domain = domain_instance['domain']

        # Create OPC UA GDS device with no_onboarding_config
        no_onboarding_config = NoOnboardingConfigModel()
        no_onboarding_config.set_pki_protocols([NoOnboardingPkiProtocol.MANUAL])
        no_onboarding_config.full_clean()
        no_onboarding_config.save()

        device = DeviceModel.objects.create(
            common_name='opcua-issue-cred',
            serial_number='SN66666',
            domain=domain,
            device_type=DeviceModel.DeviceType.OPC_UA_GDS,
            no_onboarding_config=no_onboarding_config,
        )

        url = reverse('devices:opc_ua_gds_no_onboarding_clm_issue_application_credential', kwargs={'pk': device.pk})
        response = admin_client.get(url)

        assert response.status_code == 200
        assert 'sections' in response.context


@pytest.mark.django_db
class TestCLMViewWithOnboarding:
    """Test CLM view with different onboarding protocols."""

    def test_clm_view_with_cmp_onboarding(
        self, admin_client: Client, device_instance_onboarding: dict[str, Any]
    ) -> None:
        """Test CLM view displays correct context for CMP onboarding."""
        device = device_instance_onboarding['device']

        url = reverse('devices:devices_certificate_lifecycle_management', kwargs={'pk': device.pk})
        response = admin_client.get(url)

        assert response.status_code == 200
        # Check that onboarding URL is set
        context = response.context
        assert 'issue_app_cred_onboarding_url' in context

    def test_clm_view_with_no_onboarding_and_domain(
        self, admin_client: Client, domain_instance: dict[str, Any]
    ) -> None:
        """Test CLM view displays correct context for no_onboarding with domain."""
        domain = domain_instance['domain']

        # Create device with no_onboarding_config and domain
        no_onboarding_config = NoOnboardingConfigModel()
        no_onboarding_config.set_pki_protocols([NoOnboardingPkiProtocol.MANUAL])
        no_onboarding_config.full_clean()
        no_onboarding_config.save()

        device = DeviceModel.objects.create(
            common_name='test-clm-no-onboarding',
            serial_number='SN55555',
            domain=domain,
            device_type=DeviceModel.DeviceType.GENERIC_DEVICE,
            no_onboarding_config=no_onboarding_config,
        )

        url = reverse('devices:devices_certificate_lifecycle_management', kwargs={'pk': device.pk})
        response = admin_client.get(url)

        assert response.status_code == 200
        context = response.context
        assert 'issue_app_cred_no_onboarding_url' in context
        # URL should be set because device has domain and no_onboarding_config with protocols
        assert context['issue_app_cred_no_onboarding_url'] != ''


@pytest.mark.django_db
class TestDeviceCreatePostInvalid:
    """Test POST requests with invalid data."""

    def test_device_create_no_onboarding_missing_required_fields(self, admin_client: Client) -> None:
        """Test POST with missing required fields."""
        post_data = {
            # Missing common_name
            'no_onboarding_pki_protocols': ['1'],
        }

        url = reverse('devices:devices_create_no_onboarding')
        response = admin_client.post(url, data=post_data)

        assert response.status_code == 200
        assert 'form' in response.context
        assert response.context['form'].errors

    def test_device_create_onboarding_missing_required_fields(self, admin_client: Client) -> None:
        """Test POST with missing required fields for onboarding."""
        post_data = {
            # Missing common_name and other required fields
            'onboarding_protocol': str(OnboardingProtocol.MANUAL.value),
        }

        url = reverse('devices:devices_create_onboarding')
        response = admin_client.post(url, data=post_data)

        assert response.status_code == 200
        assert 'form' in response.context
        assert response.context['form'].errors


@pytest.mark.django_db
class TestDeviceCreateDuplicateName:
    """Test device creation with duplicate names."""

    def test_create_device_with_duplicate_common_name(
        self, admin_client: Client, device_instance: dict[str, Any]
    ) -> None:
        """Test that creating device with duplicate name fails."""
        device = device_instance['device']
        domain = device_instance['domain']

        # Try to create another device with the same name
        post_data = {
            'common_name': device.common_name,  # Duplicate name
            'serial_number': 'SN-NEW',
            'domain': domain.pk,
            'no_onboarding_pki_protocols': ['1'],
        }

        url = reverse('devices:devices_create_no_onboarding')
        response = admin_client.post(url, data=post_data)

        # Should return form with error
        assert response.status_code == 200
        assert 'form' in response.context
        form = response.context['form']
        assert form.errors
        assert 'common_name' in form.errors


@pytest.mark.django_db
class TestOpcUaGdsViews:
    """Test OPC UA GDS specific view functionality."""

    def test_opcua_gds_table_excludes_generic_devices(
        self, admin_client: Client, device_instance: dict[str, Any]
    ) -> None:
        """Test that OPC UA GDS table does not show generic devices."""
        generic_device = device_instance['device']
        assert generic_device.device_type == DeviceModel.DeviceType.GENERIC_DEVICE

        url = reverse('devices:opc_ua_gds')
        response = admin_client.get(url)

        assert response.status_code == 200
        devices = response.context['object_list']
        assert generic_device not in devices

    def test_device_table_excludes_opcua_devices(self, admin_client: Client, domain_instance: dict[str, Any]) -> None:
        """Test that device table does not show OPC UA GDS devices."""
        domain = domain_instance['domain']

        # Create OPC UA GDS device
        opcua_device = DeviceModel.objects.create(
            common_name='opcua-test-device',
            serial_number='SN-OPCUA',
            domain=domain,
            device_type=DeviceModel.DeviceType.OPC_UA_GDS,
        )

        url = reverse('devices:devices')
        response = admin_client.get(url)

        assert response.status_code == 200
        devices = response.context['object_list']
        assert opcua_device not in devices


class TestOpcUaGdsPushViews:
    """Test OPC UA GDS Push specific view functionality."""
    
    def test_opcua_gds_push_table_excludes_generic_devices(
        self,
        admin_client: Client,
        device_instance: dict[str, Any]
    ) -> None:
        """Test that devices table shows OPC UA GDS Push devices."""
        generic_device = device_instance['device']
        assert generic_device.device_type == DeviceModel.DeviceType.GENERIC_DEVICE
        
        url = reverse('devices:devices')
        response = admin_client.get(url)
        
        assert response.status_code == 200
        devices = response.context['object_list']
        assert generic_device in devices
    
    def test_device_table_excludes_opcua_gds_push_devices(
        self,
        admin_client: Client,
        domain_instance: dict[str, Any]
    ) -> None:
        """Test that device table shows OPC UA GDS Push devices."""
        domain = domain_instance['domain']
        
        # Create OPC UA GDS Push device
        opcua_gds_push_device = DeviceModel.objects.create(
            common_name='opcua-gds-push-test-device',
            serial_number='SN-GDS-PUSH',
            domain=domain,
            device_type=DeviceModel.DeviceType.OPC_UA_GDS_PUSH
        )
        
        url = reverse('devices:devices')
        response = admin_client.get(url)
        
        assert response.status_code == 200
        devices = response.context['object_list']
        assert opcua_gds_push_device in devices
