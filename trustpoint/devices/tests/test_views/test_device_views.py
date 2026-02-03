"""Tests for device views."""

from typing import Any

import pytest
from django.test import Client
from django.urls import reverse

from devices.models import DeviceModel, OnboardingProtocol


@pytest.mark.django_db
class TestDeviceTableView:
    """Test DeviceTableView."""
    
    def test_device_table_view_get(self, admin_client: Client) -> None:
        """Test GET request to device table view."""
        
        url = reverse('devices:devices')
        response = admin_client.get(url)
        
        assert response.status_code == 200
        assert 'devices/devices.html' in [t.name for t in response.templates]
    
    def test_device_table_view_filters_generic_devices(
        self,
        admin_client: Client,
        device_instance: dict[str, Any]
    ) -> None:
        """Test that device table view only shows generic devices."""
        device = device_instance['device']
        assert device.device_type == DeviceModel.DeviceType.GENERIC_DEVICE
        
        url = reverse('devices:devices')
        response = admin_client.get(url)
        
        assert response.status_code == 200
        devices = response.context['object_list']
        assert device in devices
    
    def test_device_table_view_pagination(
        self,
        admin_client: Client,
        device_instance: dict[str, Any]
    ) -> None:
        """Test pagination in device table view."""
        # Create multiple devices
        domain = device_instance['domain']
        for i in range(15):
            DeviceModel.objects.create(
                common_name=f'test-device-pagination-{i}',
                serial_number=f'SN-PAGINATE-{i:05d}',
                domain=domain,
                device_type=DeviceModel.DeviceType.GENERIC_DEVICE
            )
        
        url = reverse('devices:devices')
        response = admin_client.get(url)
        
        assert response.status_code == 200
        assert 'is_paginated' in response.context or 'page_obj' in response.context


@pytest.mark.django_db
class TestOpcUaGdsTableView:
    """Test OpcUaGdsTableView."""
    
    def test_opcua_gds_table_view_get(self, admin_client: Client) -> None:
        """Test GET request to OPC UA GDS table view."""
        url = reverse('devices:opc_ua_gds')
        response = admin_client.get(url)
        
        assert response.status_code == 200
        assert 'devices/opc_ua_gds.html' in [t.name for t in response.templates]
    
    def test_opcua_gds_table_view_filters_opcua_devices(
        self,
        admin_client: Client,
        device_instance: dict[str, Any]
    ) -> None:
        """Test that OPC UA GDS table view only shows OPC UA GDS devices."""
        domain = device_instance['domain']
        
        # Create an OPC UA GDS device
        opcua_device = DeviceModel.objects.create(
            common_name='opcua-gds-device',
            serial_number='SN12345',
            domain=domain,
            device_type=DeviceModel.DeviceType.OPC_UA_GDS
        )
        
        url = reverse('devices:opc_ua_gds')
        response = admin_client.get(url)
        
        assert response.status_code == 200
        devices = response.context['object_list']
        assert opcua_device in devices
        
        # Generic devices should not be in OPC UA GDS table
        generic_device = device_instance['device']
        assert generic_device not in devices


@pytest.mark.django_db
class TestOpcUaGdsPushTableView:
    """Test OpcUaGdsPushTableView."""
    
    def test_opcua_gds_push_table_view_get(self, admin_client: Client) -> None:
        """Test GET request to OPC UA GDS Push table view."""
        url = reverse('devices:devices')
        response = admin_client.get(url)
        
        assert response.status_code == 200
        assert 'devices/devices.html' in [t.name for t in response.templates]
    
    def test_opcua_gds_push_table_view_filters_opcua_gds_push_devices(
        self,
        admin_client: Client,
        device_instance: dict[str, Any]
    ) -> None:
        """Test that devices table shows OPC UA GDS Push devices."""
        domain = device_instance['domain']
        
        # Create an OPC UA GDS Push device
        opcua_gds_push_device = DeviceModel.objects.create(
            common_name='opcua-gds-push-device',
            serial_number='SN67890',
            domain=domain,
            device_type=DeviceModel.DeviceType.OPC_UA_GDS_PUSH
        )
        
        url = reverse('devices:devices')
        response = admin_client.get(url)
        
        assert response.status_code == 200
        devices = response.context['object_list']
        assert opcua_gds_push_device in devices


@pytest.mark.django_db
class TestDeviceCreateChooseOnboardingView:
    """Test DeviceCreateChooseOnboardingView."""
    
    def test_device_create_choose_onboarding_get(self, admin_client: Client) -> None:
        """Test GET request to device create choose onboarding view."""
        url = reverse('devices:devices_create')
        response = admin_client.get(url)
        
        assert response.status_code == 200
        assert 'devices/create_choose_onboarding.html' in [t.name for t in response.templates]
    
    def test_device_create_choose_onboarding_context(
        self,
        admin_client: Client,
        domain_instance: dict[str, Any]
    ) -> None:
        """Test that view provides correct context."""
        url = reverse('devices:devices_create')
        response = admin_client.get(url)
        
        assert response.status_code == 200
        assert 'page_category' in response.context
        assert 'page_name' in response.context
        assert response.context['page_category'] == 'devices'
        assert response.context['page_name'] == 'devices'


@pytest.mark.django_db
class TestOpcUaGdsCreateChooseOnboardingView:
    """Test OpcUaGdsCreateChooseOnboardingView."""
    
    def test_opcua_gds_create_choose_onboarding_get(self, admin_client: Client) -> None:
        """Test GET request to OPC UA GDS create choose onboarding view."""
        url = reverse('devices:opc_ua_gds_create')
        response = admin_client.get(url)
        
        assert response.status_code == 200
        assert 'devices/create_choose_onboarding.html' in [t.name for t in response.templates]


@pytest.mark.django_db
class TestOpcUaGdsPushCreateChooseOnboardingView:
    """Test OpcUaGdsPushCreateChooseOnboardingView."""
    
    def test_opcua_gds_push_create_choose_onboarding_get(self, admin_client: Client) -> None:
        """Test GET request to OPC UA GDS Push create choose onboarding view."""
        from management.models import KeyStorageConfig
        
        # Ensure SOFTWARE storage is configured
        KeyStorageConfig.get_or_create_default()
        
        url = reverse('devices:opc_ua_gds_push_create_redirect')
        response = admin_client.get(url, follow=True)
        
        assert response.status_code == 200
        assert 'devices/create_choose_onboarding.html' in [t.name for t in response.templates]


@pytest.mark.django_db
class TestDeviceCreateNoOnboardingView:
    """Test DeviceCreateNoOnboardingView."""
    
    def test_device_create_no_onboarding_get(self, admin_client: Client) -> None:
        """Test GET request to device create no onboarding view."""
        url = reverse('devices:devices_create_no_onboarding')
        response = admin_client.get(url)
        
        assert response.status_code == 200
        assert 'devices/create.html' in [t.name for t in response.templates]
    
    def test_device_create_no_onboarding_post_valid(
        self,
        admin_client: Client,
        domain_instance: dict[str, Any]
    ) -> None:
        """Test POST request with valid data creates device."""
        domain = domain_instance['domain']
        
        post_data = {
            'common_name': 'new-test-device',
            'serial_number': 'SN99999',
            'domain': domain.pk,
            'no_onboarding_pki_protocols': ['1'],  # CMP_SHARED_SECRET
        }
        
        url = reverse('devices:devices_create_no_onboarding')
        response = admin_client.post(url, data=post_data)
        
        # Should redirect on success
        assert response.status_code == 302
        
        # Check device was created
        device = DeviceModel.objects.get(common_name='new-test-device')
        assert device.serial_number == 'SN99999'
        assert device.domain == domain
        assert device.device_type == DeviceModel.DeviceType.GENERIC_DEVICE
    
    def test_device_create_no_onboarding_post_invalid(
        self,
        admin_client: Client
    ) -> None:
        """Test POST request with invalid data shows errors."""
        post_data = {
            'common_name': '',  # Invalid: empty name
            'serial_number': 'SN12345',
        }
        
        url = reverse('devices:devices_create_no_onboarding')
        response = admin_client.post(url, data=post_data)
        
        # Should not redirect, should show form with errors
        assert response.status_code == 200
        assert 'form' in response.context
        assert response.context['form'].errors


@pytest.mark.django_db
class TestOpcUaGdsCreateNoOnboardingView:
    """Test OpcUaGdsCreateNoOnboardingView."""
    
    def test_opcua_gds_create_no_onboarding_get(self, admin_client: Client) -> None:
        """Test GET request to OPC UA GDS create no onboarding view."""
        url = reverse('devices:opc_ua_gds_create_no_onboarding')
        response = admin_client.get(url)
        
        assert response.status_code == 200
        assert 'devices/create.html' in [t.name for t in response.templates]
    
    def test_opcua_gds_create_no_onboarding_creates_opcua_device(
        self,
        admin_client: Client,
        domain_instance: dict[str, Any]
    ) -> None:
        """Test that OPC UA GDS view creates OPC UA GDS device type."""
        domain = domain_instance['domain']
        
        post_data = {
            'common_name': 'new-opcua-device',
            'serial_number': 'SN88888',
            'domain': domain.pk,
            'no_onboarding_pki_protocols': ['16'],  # MANUAL = 16
        }
        
        url = reverse('devices:opc_ua_gds_create_no_onboarding')
        response = admin_client.post(url, data=post_data)
        
        assert response.status_code == 302
        
        device = DeviceModel.objects.get(common_name='new-opcua-device')
        assert device.device_type == DeviceModel.DeviceType.OPC_UA_GDS


@pytest.mark.django_db
class TestDeviceCreateOnboardingView:
    """Test DeviceCreateOnboardingView."""
    
    def test_device_create_onboarding_get(self, admin_client: Client) -> None:
        """Test GET request to device create onboarding view."""
        url = reverse('devices:devices_create_onboarding')
        response = admin_client.get(url)
        
        assert response.status_code == 200
        assert 'devices/create.html' in [t.name for t in response.templates]
    
    def test_device_create_onboarding_post_valid(
        self,
        admin_client: Client,
        domain_instance: dict[str, Any]
    ) -> None:
        """Test POST request with valid data creates device with onboarding."""
        domain = domain_instance['domain']
        
        post_data = {
            'common_name': 'onboarding-device',
            'serial_number': 'SN77777',
            'domain': domain.pk,
            'onboarding_protocol': str(OnboardingProtocol.MANUAL.value),
            'onboarding_pki_protocols': ['1'],  # CMP
        }
        
        url = reverse('devices:devices_create_onboarding')
        response = admin_client.post(url, data=post_data)
        
        assert response.status_code == 302
        
        device = DeviceModel.objects.get(common_name='onboarding-device')
        assert device.onboarding_config is not None
        assert device.device_type == DeviceModel.DeviceType.GENERIC_DEVICE


@pytest.mark.django_db
class TestOpcUaGdsCreateOnboardingView:
    """Test OpcUaGdsCreateOnboardingView."""
    
    def test_opcua_gds_create_onboarding_get(self, admin_client: Client) -> None:
        """Test GET request to OPC UA GDS create onboarding view."""
        url = reverse('devices:opc_ua_gds_create_onboarding')
        response = admin_client.get(url)
        
        assert response.status_code == 200
        assert 'devices/create.html' in [t.name for t in response.templates]
    
    def test_opcua_gds_create_onboarding_creates_opcua_device(
        self,
        admin_client: Client,
        domain_instance: dict[str, Any]
    ) -> None:
        """Test that OPC UA GDS view creates OPC UA GDS device with onboarding."""
        domain = domain_instance['domain']
        
        post_data = {
            'common_name': 'opcua-onboarding-device',
            'serial_number': 'SN66666',
            'domain': domain.pk,
            'onboarding_protocol': str(OnboardingProtocol.MANUAL.value),
            'onboarding_pki_protocols': ['2'],  # EST
        }
        
        url = reverse('devices:opc_ua_gds_create_onboarding')
        response = admin_client.post(url, data=post_data)
        
        assert response.status_code == 302
        
        device = DeviceModel.objects.get(common_name='opcua-onboarding-device')
        assert device.device_type == DeviceModel.DeviceType.OPC_UA_GDS
        assert device.onboarding_config is not None


@pytest.mark.django_db
class TestOpcUaGdsPushCreateOnboardingView:
    """Test OpcUaGdsPushCreateOnboardingView."""
    
    def test_opcua_gds_push_create_onboarding_get(self, admin_client: Client) -> None:
        """Test GET request to OPC UA GDS Push create onboarding view."""
        from management.models import KeyStorageConfig
        KeyStorageConfig.get_or_create_default()
        
        url = reverse('devices:opc_ua_gds_push_create_onboarding_redirect')
        response = admin_client.get(url, follow=True)
        
        assert response.status_code == 200
        assert 'devices/create.html' in [t.name for t in response.templates]
    
    def test_opcua_gds_push_create_onboarding_creates_opcua_gds_push_device(
        self,
        admin_client: Client,
        domain_instance: dict[str, Any]
    ) -> None:
        """Test that OPC UA GDS Push view creates OPC UA GDS Push device with onboarding."""
        from management.models import KeyStorageConfig
        KeyStorageConfig.get_or_create_default()
        
        domain = domain_instance['domain']
        
        post_data = {
            'common_name': 'opcua-gds-push-onboarding-device',
            'serial_number': 'SN88888',
            'domain': domain.pk,
            'ip_address': '192.168.1.100',
            'opc_server_port': 4840,
            'opc_user': 'admin',
            'opc_password': 'password123',
        }
        
        url = reverse('devices:devices_create_opc_ua_gds_push')
        response = admin_client.post(url, data=post_data, follow=True)
        
        assert response.status_code == 200
        
        device = DeviceModel.objects.get(common_name='opcua-gds-push-onboarding-device')
        assert device.device_type == DeviceModel.DeviceType.OPC_UA_GDS_PUSH
        assert device.onboarding_config is not None
        assert device.onboarding_config.onboarding_protocol == OnboardingProtocol.OPC_GDS_PUSH
        assert device.ip_address == '192.168.1.100'
        assert device.opc_server_port == 4840


@pytest.mark.django_db
class TestDeviceCertificateLifecycleManagementSummaryView:
    """Test DeviceCertificateLifecycleManagementSummaryView."""
    
    def test_clm_summary_view_get(
        self,
        admin_client: Client,
        device_instance: dict[str, Any]
    ) -> None:
        """Test GET request to CLM summary view."""
        device = device_instance['device']
        
        url = reverse('devices:devices_certificate_lifecycle_management', kwargs={'pk': device.pk})
        response = admin_client.get(url)
        
        assert response.status_code == 200
        assert 'devices/credentials/certificate_lifecycle_management.html' in [t.name for t in response.templates]
        assert response.context['object'] == device
    
    def test_clm_summary_view_invalid_device(self, admin_client: Client) -> None:
        """Test GET request with invalid device ID returns 404."""
        url = reverse('devices:devices_certificate_lifecycle_management', kwargs={'pk': 99999})
        response = admin_client.get(url)
        
        assert response.status_code == 404


@pytest.mark.django_db
class TestOpcUaGdsCertificateLifecycleManagementSummaryView:
    """Test OpcUaGdsCertificateLifecycleManagementSummaryView."""
    
    def test_opcua_gds_clm_summary_view_get(
        self,
        admin_client: Client,
        device_instance: dict[str, Any]
    ) -> None:
        """Test GET request to OPC UA GDS CLM summary view."""
        from devices.models import NoOnboardingConfigModel, NoOnboardingPkiProtocol
        
        domain = device_instance['domain']
        
        # Create no_onboarding_config
        no_onboarding_config = NoOnboardingConfigModel()
        no_onboarding_config.set_pki_protocols([NoOnboardingPkiProtocol.MANUAL])
        no_onboarding_config.full_clean()
        no_onboarding_config.save()
        
        # Create OPC UA GDS device with no_onboarding_config
        opcua_device = DeviceModel.objects.create(
            common_name='opcua-clm-device',
            serial_number='SN55555',
            domain=domain,
            device_type=DeviceModel.DeviceType.OPC_UA_GDS,
            no_onboarding_config=no_onboarding_config
        )
        
        url = reverse('devices:opc_ua_gds_certificate_lifecycle_management', kwargs={'pk': opcua_device.pk})
        response = admin_client.get(url)
        
        assert response.status_code == 200
        assert 'devices/credentials/certificate_lifecycle_management.html' in [t.name for t in response.templates]
        assert response.context['object'] == opcua_device


@pytest.mark.django_db
class TestOpcUaGdsPushCertificateLifecycleManagementSummaryView:
    """Test OpcUaGdsPushCertificateLifecycleManagementSummaryView."""
    
    def test_opcua_gds_push_clm_summary_view_get(
        self,
        admin_client: Client,
        device_instance_onboarding: dict[str, Any]
    ) -> None:
        """Test GET request to OPC UA GDS Push CLM summary view."""
        device = device_instance_onboarding['device']
        # Change device type to GDS Push
        device.device_type = DeviceModel.DeviceType.OPC_UA_GDS_PUSH
        device.save()
        
        url = reverse('devices:opc_ua_gds_push_certificate_lifecycle_management', kwargs={'pk': device.pk})
        response = admin_client.get(url)
        
        assert response.status_code == 200
        assert 'devices/credentials/certificate_lifecycle_management.html' in [t.name for t in response.templates]
        assert response.context['object'] == device
