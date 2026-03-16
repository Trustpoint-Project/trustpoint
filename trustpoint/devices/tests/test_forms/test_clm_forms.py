"""Tests for Certificate Lifecycle Management (CLM) Device forms."""

from typing import Any

import pytest
from django.forms import ValidationError

from devices.forms import ClmDeviceModelNoOnboardingForm, ClmDeviceModelOnboardingForm, ClmDeviceModelOpcUaGdsPushOnboardingForm
from devices.models import (
    DeviceModel,
    NoOnboardingPkiProtocol,
    OnboardingPkiProtocol,
    OnboardingProtocol,
    OnboardingStatus,
)


@pytest.mark.django_db
class TestClmDeviceModelOnboardingForm:
    """Test ClmDeviceModelOnboardingForm for devices with onboarding."""
    
    def test_form_initialization(self, device_instance_onboarding: dict[str, Any]) -> None:
        """Test form initializes correctly with device instance."""
        device = device_instance_onboarding['device']
        
        form = ClmDeviceModelOnboardingForm(instance=device)
        
        assert form.instance == device
        assert 'common_name' in form.fields
        assert 'serial_number' in form.fields
        assert 'domain' in form.fields
        assert 'onboarding_protocol' in form.fields
        assert 'pki_protocol_cmp' in form.fields
        assert 'pki_protocol_est' in form.fields
    
    def test_save_with_manual_onboarding_clears_secrets(
        self, 
        device_instance_onboarding: dict[str, Any]
    ) -> None:
        """Test save() clears secrets when protocol is MANUAL."""
        device = device_instance_onboarding['device']
        domain = device_instance_onboarding['domain']
        
        # Set protocol to CMP first so we can set a secret
        device.onboarding_config.onboarding_protocol = OnboardingProtocol.CMP_SHARED_SECRET
        device.onboarding_config.cmp_shared_secret = 'some_secret'
        device.onboarding_config.save()
        
        # Verify secret is set
        assert device.onboarding_config.cmp_shared_secret == 'some_secret'
        
        form_data = {
            'common_name': 'updated-device',
            'serial_number': 'SN12345',
            'domain': domain.pk,
            'onboarding_protocol': str(OnboardingProtocol.MANUAL.value),
            'onboarding_status': 'pending',
            'pki_protocol_cmp': True,
            'pki_protocol_est': False,
        }
        
        form = ClmDeviceModelOnboardingForm(data=form_data, instance=device)
        assert form.is_valid()
        
        form.save(OnboardingProtocol.MANUAL)
        device.refresh_from_db()
        
        assert device.onboarding_config.cmp_shared_secret == ''
        assert device.onboarding_config.est_password == ''
        assert device.common_name == 'updated-device'
    
    def test_save_with_cmp_generates_shared_secret(
        self,
        device_instance_onboarding: dict[str, Any]
    ) -> None:
        """Test save() generates CMP shared secret when needed."""
        device = device_instance_onboarding['device']
        domain = device_instance_onboarding['domain']
        
        # Clear any existing secrets
        device.onboarding_config.cmp_shared_secret = ''
        device.onboarding_config.est_password = ''
        device.onboarding_config.save()
        
        form_data = {
            'common_name': 'cmp-device',
            'serial_number': 'SN67890',
            'domain': domain.pk,
            'onboarding_protocol': str(OnboardingProtocol.CMP_SHARED_SECRET.value),
            'onboarding_status': 'pending',
            'pki_protocol_cmp': True,
            'pki_protocol_est': False,
        }
        
        form = ClmDeviceModelOnboardingForm(data=form_data, instance=device)
        assert form.is_valid()
        
        form.save(OnboardingProtocol.CMP_SHARED_SECRET)
        device.refresh_from_db()
        
        assert device.onboarding_config.cmp_shared_secret != ''
        assert device.onboarding_config.est_password == ''
    
    def test_save_with_est_generates_password(
        self,
        device_instance_onboarding: dict[str, Any]
    ) -> None:
        """Test save() generates EST password when needed."""
        device = device_instance_onboarding['device']
        domain = device_instance_onboarding['domain']
        
        # Clear any existing secrets
        device.onboarding_config.cmp_shared_secret = ''
        device.onboarding_config.est_password = ''
        device.onboarding_config.save()
        
        form_data = {
            'common_name': 'est-device',
            'serial_number': 'SN11111',
            'domain': domain.pk,
            'onboarding_protocol': str(OnboardingProtocol.EST_USERNAME_PASSWORD.value),
            'onboarding_status': 'pending',
            'pki_protocol_cmp': False,
            'pki_protocol_est': True,
        }
        
        form = ClmDeviceModelOnboardingForm(data=form_data, instance=device)
        assert form.is_valid()
        
        form.save(OnboardingProtocol.EST_USERNAME_PASSWORD)
        device.refresh_from_db()
        
        assert device.onboarding_config.cmp_shared_secret == ''
        assert device.onboarding_config.est_password != ''
    
    def test_save_updates_pki_protocols_cmp_only(
        self,
        device_instance_onboarding: dict[str, Any]
    ) -> None:
        """Test save() correctly updates PKI protocols - CMP only."""
        device = device_instance_onboarding['device']
        domain = device_instance_onboarding['domain']
        
        form_data = {
            'common_name': device.common_name,
            'serial_number': device.serial_number,
            'domain': domain.pk,
            'onboarding_protocol': str(OnboardingProtocol.MANUAL.value),
            'onboarding_status': 'pending',
            'pki_protocol_cmp': True,
            'pki_protocol_est': False,
        }
        
        form = ClmDeviceModelOnboardingForm(data=form_data, instance=device)
        assert form.is_valid()
        
        form.save(OnboardingProtocol.MANUAL)
        device.refresh_from_db()
        
        assert device.onboarding_config.has_pki_protocol(OnboardingPkiProtocol.CMP)
        assert not device.onboarding_config.has_pki_protocol(OnboardingPkiProtocol.EST)
    
    def test_save_updates_pki_protocols_est_only(
        self,
        device_instance_onboarding: dict[str, Any]
    ) -> None:
        """Test save() correctly updates PKI protocols - EST only."""
        device = device_instance_onboarding['device']
        domain = device_instance_onboarding['domain']
        
        form_data = {
            'common_name': device.common_name,
            'serial_number': device.serial_number,
            'domain': domain.pk,
            'onboarding_protocol': str(OnboardingProtocol.MANUAL.value),
            'onboarding_status': 'pending',
            'pki_protocol_cmp': False,
            'pki_protocol_est': True,
        }
        
        form = ClmDeviceModelOnboardingForm(data=form_data, instance=device)
        assert form.is_valid()
        
        form.save(OnboardingProtocol.MANUAL)
        device.refresh_from_db()
        
        assert not device.onboarding_config.has_pki_protocol(OnboardingPkiProtocol.CMP)
        assert device.onboarding_config.has_pki_protocol(OnboardingPkiProtocol.EST)
    
    def test_save_updates_pki_protocols_both(
        self,
        device_instance_onboarding: dict[str, Any]
    ) -> None:
        """Test save() correctly updates PKI protocols - both CMP and EST."""
        device = device_instance_onboarding['device']
        domain = device_instance_onboarding['domain']
        
        form_data = {
            'common_name': device.common_name,
            'serial_number': device.serial_number,
            'domain': domain.pk,
            'onboarding_protocol': str(OnboardingProtocol.MANUAL.value),
            'onboarding_status': 'pending',
            'pki_protocol_cmp': True,
            'pki_protocol_est': True,
        }
        
        form = ClmDeviceModelOnboardingForm(data=form_data, instance=device)
        assert form.is_valid()
        
        form.save(OnboardingProtocol.MANUAL)
        device.refresh_from_db()
        
        assert device.onboarding_config.has_pki_protocol(OnboardingPkiProtocol.CMP)
        assert device.onboarding_config.has_pki_protocol(OnboardingPkiProtocol.EST)
    
    def test_save_without_onboarding_config_raises_error(
        self,
        device_instance: dict[str, Any]
    ) -> None:
        """Test save() raises ValidationError when device has no onboarding config."""
        device = device_instance['device']
        domain = device_instance['domain']
        
        form_data = {
            'common_name': device.common_name,
            'serial_number': device.serial_number,
            'domain': domain.pk,
            'onboarding_protocol': str(OnboardingProtocol.MANUAL.value),
            'onboarding_status': 'pending',
            'pki_protocol_cmp': True,
            'pki_protocol_est': False,
        }
        
        form = ClmDeviceModelOnboardingForm(data=form_data, instance=device)
        assert form.is_valid()
        
        with pytest.raises(ValidationError):
            form.save(OnboardingProtocol.MANUAL)


@pytest.mark.django_db
class TestClmDeviceModelNoOnboardingForm:
    """Test ClmDeviceModelNoOnboardingForm for devices without onboarding."""
    
    def test_form_initialization(self, device_instance: dict[str, Any]) -> None:
        """Test form initializes correctly with device instance."""
        device = device_instance['device']
        
        form = ClmDeviceModelNoOnboardingForm(instance=device)
        
        assert form.instance == device
        assert 'common_name' in form.fields
        assert 'serial_number' in form.fields
        assert 'domain' in form.fields
        assert 'pki_protocol_cmp' in form.fields
        assert 'pki_protocol_est' in form.fields
        assert 'pki_protocol_manual' in form.fields
    
    def test_save_updates_device_fields(self, device_instance: dict[str, Any]) -> None:
        """Test save() updates device common_name, serial_number, and domain."""
        device = device_instance['device']
        domain = device_instance['domain']
        
        form_data = {
            'common_name': 'updated-no-onboarding',
            'serial_number': 'SN99999',
            'domain': domain.pk,
            'pki_protocol_cmp': False,
            'pki_protocol_est': False,
            'pki_protocol_manual': True,
        }
        
        form = ClmDeviceModelNoOnboardingForm(data=form_data, instance=device)
        assert form.is_valid()
        
        form.save()
        device.refresh_from_db()
        
        assert device.common_name == 'updated-no-onboarding'
        assert device.serial_number == 'SN99999'
        assert device.domain == domain
    
    def test_save_with_cmp_protocol_generates_secret(
        self,
        device_instance: dict[str, Any]
    ) -> None:
        """Test save() generates CMP shared secret when protocol is enabled."""
        device = device_instance['device']
        domain = device_instance['domain']
        
        # Clear existing secret
        device.no_onboarding_config.cmp_shared_secret = ''
        device.no_onboarding_config.save()
        
        form_data = {
            'common_name': device.common_name,
            'serial_number': device.serial_number,
            'domain': domain.pk,
            'pki_protocol_cmp': True,
            'pki_protocol_est': False,
            'pki_protocol_manual': False,
        }
        
        form = ClmDeviceModelNoOnboardingForm(data=form_data, instance=device)
        assert form.is_valid()
        
        form.save()
        device.refresh_from_db()
        
        assert device.no_onboarding_config.cmp_shared_secret != ''
        assert device.no_onboarding_config.has_pki_protocol(NoOnboardingPkiProtocol.CMP_SHARED_SECRET)
    
    def test_save_without_cmp_clears_secret(
        self,
        device_instance: dict[str, Any]
    ) -> None:
        """Test save() clears CMP shared secret when protocol is disabled."""
        device = device_instance['device']
        domain = device_instance['domain']
        
        # Set a secret first
        device.no_onboarding_config.cmp_shared_secret = 'test_secret'
        
        form_data = {
            'common_name': device.common_name,
            'serial_number': device.serial_number,
            'domain': domain.pk,
            'pki_protocol_cmp': False,
            'pki_protocol_est': False,
            'pki_protocol_manual': True,
        }
        
        form = ClmDeviceModelNoOnboardingForm(data=form_data, instance=device)
        assert form.is_valid()
        
        form.save()
        device.refresh_from_db()
        
        assert device.no_onboarding_config.cmp_shared_secret == ''
    
    def test_save_with_est_protocol_generates_password(
        self,
        device_instance: dict[str, Any]
    ) -> None:
        """Test save() generates EST password when protocol is enabled."""
        device = device_instance['device']
        domain = device_instance['domain']
        
        # Clear existing password
        device.no_onboarding_config.est_password = ''
        device.no_onboarding_config.save()
        
        form_data = {
            'common_name': device.common_name,
            'serial_number': device.serial_number,
            'domain': domain.pk,
            'pki_protocol_cmp': False,
            'pki_protocol_est': True,
            'pki_protocol_manual': False,
        }
        
        form = ClmDeviceModelNoOnboardingForm(data=form_data, instance=device)
        assert form.is_valid()
        
        form.save()
        device.refresh_from_db()
        
        assert device.no_onboarding_config.est_password != ''
        assert device.no_onboarding_config.has_pki_protocol(NoOnboardingPkiProtocol.EST_USERNAME_PASSWORD)
    
    def test_save_without_est_clears_password(
        self,
        device_instance: dict[str, Any]
    ) -> None:
        """Test save() clears EST password when protocol is disabled."""
        device = device_instance['device']
        domain = device_instance['domain']
        
        # Set a password first
        device.no_onboarding_config.est_password = 'test_password'
        
        form_data = {
            'common_name': device.common_name,
            'serial_number': device.serial_number,
            'domain': domain.pk,
            'pki_protocol_cmp': False,
            'pki_protocol_est': False,
            'pki_protocol_manual': True,
        }
        
        form = ClmDeviceModelNoOnboardingForm(data=form_data, instance=device)
        assert form.is_valid()
        
        form.save()
        device.refresh_from_db()
        
        assert device.no_onboarding_config.est_password == ''
    
    def test_save_with_manual_protocol(
        self,
        device_instance: dict[str, Any]
    ) -> None:
        """Test save() adds MANUAL protocol when enabled."""
        device = device_instance['device']
        domain = device_instance['domain']
        
        form_data = {
            'common_name': device.common_name,
            'serial_number': device.serial_number,
            'domain': domain.pk,
            'pki_protocol_cmp': False,
            'pki_protocol_est': False,
            'pki_protocol_manual': True,
        }
        
        form = ClmDeviceModelNoOnboardingForm(data=form_data, instance=device)
        assert form.is_valid()
        
        form.save()
        device.refresh_from_db()
        
        assert device.no_onboarding_config.has_pki_protocol(NoOnboardingPkiProtocol.MANUAL)
    
    def test_save_with_all_protocols(
        self,
        device_instance: dict[str, Any]
    ) -> None:
        """Test save() correctly handles all protocols enabled."""
        device = device_instance['device']
        domain = device_instance['domain']
        
        # Clear existing secrets
        device.no_onboarding_config.cmp_shared_secret = ''
        device.no_onboarding_config.est_password = ''
        device.no_onboarding_config.save()
        
        form_data = {
            'common_name': device.common_name,
            'serial_number': device.serial_number,
            'domain': domain.pk,
            'pki_protocol_cmp': True,
            'pki_protocol_est': True,
            'pki_protocol_manual': True,
        }
        
        form = ClmDeviceModelNoOnboardingForm(data=form_data, instance=device)
        assert form.is_valid()
        
        form.save()
        device.refresh_from_db()
        
        assert device.no_onboarding_config.cmp_shared_secret != ''
        assert device.no_onboarding_config.est_password != ''
        assert device.no_onboarding_config.has_pki_protocol(NoOnboardingPkiProtocol.CMP_SHARED_SECRET)
        assert device.no_onboarding_config.has_pki_protocol(NoOnboardingPkiProtocol.EST_USERNAME_PASSWORD)
        assert device.no_onboarding_config.has_pki_protocol(NoOnboardingPkiProtocol.MANUAL)
    
    def test_save_without_no_onboarding_config_raises_error(
        self,
        device_instance_onboarding: dict[str, Any]
    ) -> None:
        """Test save() raises ValidationError when device has no no_onboarding_config."""
        device = device_instance_onboarding['device']
        domain = device_instance_onboarding['domain']
        
        form_data = {
            'common_name': device.common_name,
            'serial_number': device.serial_number,
            'domain': domain.pk,
            'pki_protocol_cmp': True,
            'pki_protocol_est': False,
            'pki_protocol_manual': False,
        }
        
        form = ClmDeviceModelNoOnboardingForm(data=form_data, instance=device)
        assert form.is_valid()
        
        with pytest.raises(ValidationError):
            form.save()


@pytest.mark.django_db
class TestClmDeviceModelOpcUaGdsPushOnboardingForm:
    """Test ClmDeviceModelOpcUaGdsPushOnboardingForm for OPC UA GDS Push devices with onboarding."""

    def test_form_initialization(self, device_instance_onboarding: dict[str, Any]) -> None:
        """Test form initializes correctly with GDS push device instance."""
        device = device_instance_onboarding['device']
        # Modify device to be GDS push type
        device.device_type = DeviceModel.DeviceType.OPC_UA_GDS_PUSH
        device.ip_address = '192.168.1.100'
        device.opc_server_port = 4840
        device.onboarding_config.onboarding_protocol = OnboardingProtocol.OPC_GDS_PUSH
        device.onboarding_config.clear_pki_protocols()
        device.onboarding_config.add_pki_protocol(OnboardingPkiProtocol.OPC_GDS_PUSH)
        device.save()
        device.onboarding_config.save()

        form = ClmDeviceModelOpcUaGdsPushOnboardingForm(instance=device)

        assert form.instance == device
        assert 'common_name' in form.fields
        assert 'serial_number' in form.fields
        assert 'domain' in form.fields
        assert 'ip_address' in form.fields
        assert 'opc_server_port' in form.fields
        assert 'opc_trust_store' in form.fields
        assert 'onboarding_protocol' in form.fields
        assert 'onboarding_status' in form.fields
        assert 'pki_protocol_opc_gds_push' in form.fields

    def test_form_initial_values(self, device_instance_onboarding: dict[str, Any]) -> None:
        """Test that form is initialized with correct values from device."""
        device = device_instance_onboarding['device']
        # Modify device to be GDS push type
        device.device_type = DeviceModel.DeviceType.OPC_UA_GDS_PUSH
        device.ip_address = '192.168.1.100'
        device.opc_server_port = 4840
        device.onboarding_config.onboarding_protocol = OnboardingProtocol.OPC_GDS_PUSH
        device.onboarding_config.clear_pki_protocols()
        device.onboarding_config.add_pki_protocol(OnboardingPkiProtocol.OPC_GDS_PUSH)
        device.save()
        device.onboarding_config.save()

        form = ClmDeviceModelOpcUaGdsPushOnboardingForm(instance=device)

        assert form.initial['common_name'] == device.common_name
        assert form.initial['serial_number'] == device.serial_number
        assert form.initial['domain'] == device.domain
        assert form.initial['ip_address'] == device.ip_address
        assert form.initial['opc_server_port'] == device.opc_server_port
        assert form.initial['opc_trust_store'] == device.onboarding_config.opc_trust_store
        assert 'OPC - GDS Push' in form.initial['onboarding_protocol']
        assert form.initial['pki_protocol_opc_gds_push'] is True

    def test_save_updates_device(self, device_instance_onboarding: dict[str, Any], domain_instance: dict[str, Any]) -> None:
        """Test save() updates device with form data."""
        device = device_instance_onboarding['device']
        # Modify device to be GDS push type
        device.device_type = DeviceModel.DeviceType.OPC_UA_GDS_PUSH
        device.ip_address = '192.168.1.100'
        device.opc_server_port = 4840
        device.onboarding_config.onboarding_protocol = OnboardingProtocol.OPC_GDS_PUSH
        device.onboarding_config.clear_pki_protocols()
        device.onboarding_config.add_pki_protocol(OnboardingPkiProtocol.OPC_GDS_PUSH)
        device.save()
        device.onboarding_config.save()
        
        new_domain = domain_instance['domain']

        form_data = {
            'common_name': 'updated-gds-device',
            'serial_number': 'NEW-SN-123',
            'domain': new_domain.pk,
            'ip_address': '10.0.0.100',
            'opc_server_port': 4841,
            # 'opc_trust_store': '',  # No truststore - commented out since it's not required
            'onboarding_status': OnboardingStatus.PENDING.label,  # Required field
            'pki_protocol_opc_gds_push': True,
        }

        form = ClmDeviceModelOpcUaGdsPushOnboardingForm(data=form_data, instance=device)
        assert form.is_valid()

        form.save()

        device.refresh_from_db()
        assert device.common_name == 'updated-gds-device'
        assert device.serial_number == 'NEW-SN-123'
        assert device.domain == new_domain
        assert device.ip_address == '10.0.0.100'
        assert device.opc_server_port == 4841
        assert device.onboarding_config.opc_trust_store is None
        assert device.onboarding_config.has_pki_protocol(OnboardingPkiProtocol.OPC_GDS_PUSH)

    def test_save_without_onboarding_config_raises_error(self, device_instance: dict[str, Any]) -> None:
        """Test save() raises ValidationError when device has no onboarding config."""
        device = device_instance['device']  # Regular device without onboarding

        form = ClmDeviceModelOpcUaGdsPushOnboardingForm(instance=device)

        with pytest.raises(ValidationError) as exc_info:
            form.save()

        assert 'Expected DeviceModel that is configured to use onboarding' in str(exc_info.value)

    def test_form_with_invalid_ip_address(self, device_instance_onboarding: dict[str, Any]) -> None:
        """Test form validation with invalid IP address."""
        device = device_instance_onboarding['device']
        # Modify device to be GDS push type
        device.device_type = DeviceModel.DeviceType.OPC_UA_GDS_PUSH
        device.ip_address = '192.168.1.100'
        device.opc_server_port = 4840
        device.onboarding_config.onboarding_protocol = OnboardingProtocol.OPC_GDS_PUSH
        device.onboarding_config.clear_pki_protocols()
        device.onboarding_config.add_pki_protocol(OnboardingPkiProtocol.OPC_GDS_PUSH)
        device.save()
        device.onboarding_config.save()

        form_data = {
            'common_name': device.common_name,
            'ip_address': 'invalid-ip-address',
            'opc_server_port': device.opc_server_port,
            'pki_protocol_opc_gds_push': True,
        }

        form = ClmDeviceModelOpcUaGdsPushOnboardingForm(data=form_data, instance=device)
        assert not form.is_valid()
        assert 'ip_address' in form.errors

    def test_form_with_invalid_port(self, device_instance_onboarding: dict[str, Any]) -> None:
        """Test form validation with invalid port number."""
        device = device_instance_onboarding['device']
        # Modify device to be GDS push type
        device.device_type = DeviceModel.DeviceType.OPC_UA_GDS_PUSH
        device.ip_address = '192.168.1.100'
        device.opc_server_port = 4840
        device.onboarding_config.onboarding_protocol = OnboardingProtocol.OPC_GDS_PUSH
        device.onboarding_config.clear_pki_protocols()
        device.onboarding_config.add_pki_protocol(OnboardingPkiProtocol.OPC_GDS_PUSH)
        device.save()
        device.onboarding_config.save()

        form_data = {
            'common_name': device.common_name,
            'ip_address': device.ip_address,
            'opc_server_port': 99999,  # Invalid port
            'pki_protocol_opc_gds_push': True,
        }

        form = ClmDeviceModelOpcUaGdsPushOnboardingForm(data=form_data, instance=device)
        assert not form.is_valid()
        assert 'opc_server_port' in form.errors
