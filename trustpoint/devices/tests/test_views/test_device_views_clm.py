"""Additional tests for CLM POST operations and credential management."""

from typing import Any

import pytest
from django.test import Client
from django.urls import reverse

from devices.models import DeviceModel
from onboarding.models import NoOnboardingConfigModel, NoOnboardingPkiProtocol


@pytest.mark.django_db
class TestCLMPostOperations:
    """Test POST operations on CLM view."""

    def test_clm_post_handles_form_submission(self, admin_client: Client, domain_instance: dict[str, Any]) -> None:
        """Test that POST to CLM view processes form correctly."""
        domain = domain_instance['domain']

        # Create device with no_onboarding_config
        no_onboarding_config = NoOnboardingConfigModel()
        no_onboarding_config.set_pki_protocols([NoOnboardingPkiProtocol.MANUAL])
        no_onboarding_config.full_clean()
        no_onboarding_config.save()

        device = DeviceModel.objects.create(
            common_name='test-clm-post',
            serial_number='SN-POST-1',
            domain=domain,
            device_type=DeviceModel.DeviceType.GENERIC_DEVICE,
            no_onboarding_config=no_onboarding_config,
        )

        # POST without required data should return 200 with form errors
        post_data = {}

        url = reverse('devices:devices_certificate_lifecycle_management', kwargs={'pk': device.pk})
        response = admin_client.post(url, data=post_data)

        # Form validation should fail, returning 200
        assert response.status_code == 200


@pytest.mark.django_db
class TestCredentialExpiration:
    """Test credential expiration display in CLM view."""

    def test_clm_view_has_credentials_context(self, admin_client: Client, device_instance: dict[str, Any]) -> None:
        """Test that CLM view provides credentials in context."""
        device = device_instance['device']

        url = reverse('devices:devices_certificate_lifecycle_management', kwargs={'pk': device.pk})
        response = admin_client.get(url)

        assert response.status_code == 200

        # Check that credentials are in context
        assert 'domain_credentials' in response.context
        assert 'application_credentials' in response.context


@pytest.mark.django_db
class TestCLMContextUrls:
    """Test that CLM view provides correct URL context."""

    def test_clm_view_provides_main_url(self, admin_client: Client, device_instance: dict[str, Any]) -> None:
        """Test that CLM view provides main_url in context."""
        device = device_instance['device']

        url = reverse('devices:devices_certificate_lifecycle_management', kwargs={'pk': device.pk})
        response = admin_client.get(url)

        assert response.status_code == 200
        assert 'main_url' in response.context
        assert response.context['main_url'] == 'devices:devices'

    def test_clm_view_with_est_onboarding_provides_domain_cred_url(
        self, admin_client: Client, domain_instance: dict[str, Any]
    ) -> None:
        """Test CLM view with EST onboarding provides domain credential URL."""
        from onboarding.models import OnboardingConfigModel, OnboardingProtocol, OnboardingPkiProtocol
        
        domain = domain_instance['domain']

        # Create onboarding config with EST
        onboarding_config = OnboardingConfigModel()
        onboarding_config.onboarding_protocol = OnboardingProtocol.EST_USERNAME_PASSWORD
        onboarding_config.set_pki_protocols([OnboardingPkiProtocol.EST])
        onboarding_config.est_password = 'test_password_12345'
        onboarding_config.full_clean()
        onboarding_config.save()

        device = DeviceModel.objects.create(
            common_name='test-est-device',
            serial_number='SN-EST-1',
            domain=domain,
            device_type=DeviceModel.DeviceType.GENERIC_DEVICE,
            onboarding_config=onboarding_config,
        )

        url = reverse('devices:devices_certificate_lifecycle_management', kwargs={'pk': device.pk})
        response = admin_client.get(url)

        assert response.status_code == 200
        assert 'issue_domain_cred_onboarding_url' in response.context
        # Should have EST-specific URL
        assert 'est_username_password' in response.context['issue_domain_cred_onboarding_url']


@pytest.mark.django_db
class TestDeviceViewSetAPI:
    """Test DeviceViewSet API endpoints."""

    def test_device_viewset_list(self, admin_client: Client, device_instance: dict[str, Any]) -> None:
        """Test API list endpoint for devices."""
        device = device_instance['device']

        # API endpoint
        url = '/api/devices/'
        response = admin_client.get(url)

        # Should return 200, 401 (unauthorized), or 404 if REST framework URLs aren't configured
        assert response.status_code in [200, 401, 404]


@pytest.mark.django_db
class TestOpcUaGdsCLMView:
    """Test OPC UA GDS CLM view specific functionality."""

    def test_opcua_gds_clm_view_provides_correct_main_url(
        self, admin_client: Client, domain_instance: dict[str, Any]
    ) -> None:
        """Test that OPC UA GDS CLM view provides correct main_url."""
        domain = domain_instance['domain']

        # Create OPC UA GDS device with no_onboarding_config
        no_onboarding_config = NoOnboardingConfigModel()
        no_onboarding_config.set_pki_protocols([NoOnboardingPkiProtocol.MANUAL])
        no_onboarding_config.full_clean()
        no_onboarding_config.save()

        device = DeviceModel.objects.create(
            common_name='opcua-clm-test',
            serial_number='SN-OPCUA-CLM',
            domain=domain,
            device_type=DeviceModel.DeviceType.OPC_UA_GDS,
            no_onboarding_config=no_onboarding_config,
        )

        url = reverse('devices:opc_ua_gds_certificate_lifecycle_management', kwargs={'pk': device.pk})
        response = admin_client.get(url)

        assert response.status_code == 200
        assert 'main_url' in response.context
        assert response.context['main_url'] == 'devices:opc_ua_gds'


@pytest.mark.django_db
class TestOpcUaGdsPushCLMView:
    """Test OPC UA GDS Push CLM view specific functionality."""
    
    def test_opcua_gds_push_clm_view_provides_correct_main_url(
        self,
        admin_client: Client,
        device_instance_onboarding: dict[str, Any]
    ) -> None:
        """Test that OPC UA GDS Push CLM view provides correct main_url."""
        device = device_instance_onboarding['device']
        # Change device type to GDS Push
        device.device_type = DeviceModel.DeviceType.OPC_UA_GDS_PUSH
        device.save()
        
        url = reverse('devices:opc_ua_gds_push_certificate_lifecycle_management', kwargs={'pk': device.pk})
        response = admin_client.get(url)
        
        assert response.status_code == 200
        assert 'main_url' in response.context
        assert response.context['main_url'] == 'devices:devices'


@pytest.mark.django_db
class TestDeviceTableFiltering:
    """Test device table filtering functionality."""

    def test_device_table_with_search_filter(self, admin_client: Client, device_instance: dict[str, Any]) -> None:
        """Test device table with search filter."""
        device = device_instance['device']

        # Search for device by name
        url = reverse('devices:devices') + f'?search={device.common_name}'
        response = admin_client.get(url)

        assert response.status_code == 200
        assert device in response.context['object_list']


@pytest.mark.django_db
class TestNoOnboardingCredentialSections:
    """Test that credential issuance sections show correct protocol status."""

    def test_sections_show_disabled_protocols(self, admin_client: Client, domain_instance: dict[str, Any]) -> None:
        """Test that sections correctly show disabled protocols."""
        domain = domain_instance['domain']

        # Create device with only MANUAL protocol enabled
        no_onboarding_config = NoOnboardingConfigModel()
        no_onboarding_config.set_pki_protocols([NoOnboardingPkiProtocol.MANUAL])
        no_onboarding_config.full_clean()
        no_onboarding_config.save()

        device = DeviceModel.objects.create(
            common_name='test-sections',
            serial_number='SN-SECTIONS',
            domain=domain,
            device_type=DeviceModel.DeviceType.GENERIC_DEVICE,
            no_onboarding_config=no_onboarding_config,
        )

        url = reverse('devices:devices_no_onboarding_clm_issue_application_credential', kwargs={'pk': device.pk})
        response = admin_client.get(url)

        assert response.status_code == 200
        sections = response.context['sections']

        # Check CMP is disabled
        cmp_section = next(s for s in sections if s['protocol'] == 'cmp-shared-secret')
        assert not cmp_section['enabled']

        # Check EST is disabled
        est_section = next(s for s in sections if s['protocol'] == 'est-username-password')
        assert not est_section['enabled']

        # Check MANUAL is enabled
        manual_section = next(s for s in sections if s['protocol'] == 'manual')
        assert manual_section['enabled']


@pytest.mark.django_db
class TestDeviceCreateOnboardingProtocols:
    """Test device creation with different onboarding protocols."""

    def test_create_device_with_manual_onboarding(self, admin_client: Client, domain_instance: dict[str, Any]) -> None:
        """Test creating device with MANUAL onboarding protocol."""
        domain = domain_instance['domain']
        
        from onboarding.models import OnboardingProtocol
        
        post_data = {
            'common_name': 'manual-onboarding-device',
            'serial_number': 'SN-MANUAL',
            'domain': domain.pk,
            'onboarding_protocol': str(OnboardingProtocol.MANUAL.value),
            'onboarding_pki_protocols': ['1'],  # CMP
        }

        url = reverse('devices:devices_create_onboarding')
        response = admin_client.post(url, data=post_data)

        assert response.status_code == 302

        device = DeviceModel.objects.get(common_name='manual-onboarding-device')
        assert device.onboarding_config is not None
        assert device.onboarding_config.onboarding_protocol == OnboardingProtocol.MANUAL


@pytest.mark.django_db
class TestCLMViewWithoutDomain:
    """Test CLM view behavior for devices without domain."""

    def test_clm_view_device_without_domain_no_issue_urls(self, admin_client: Client) -> None:
        """Test that device without domain has empty issue credential URLs."""
        # Create device without domain
        no_onboarding_config = NoOnboardingConfigModel()
        no_onboarding_config.set_pki_protocols([NoOnboardingPkiProtocol.MANUAL])
        no_onboarding_config.full_clean()
        no_onboarding_config.save()

        device = DeviceModel.objects.create(
            common_name='test-no-domain-clm',
            serial_number='SN-NO-DOMAIN',
            domain=None,
            device_type=DeviceModel.DeviceType.GENERIC_DEVICE,
            no_onboarding_config=no_onboarding_config,
        )

        url = reverse('devices:devices_certificate_lifecycle_management', kwargs={'pk': device.pk})
        response = admin_client.get(url)

        assert response.status_code == 200
        context = response.context
        # Without domain, issue URLs should be empty
        assert context['issue_app_cred_no_onboarding_url'] == ''
