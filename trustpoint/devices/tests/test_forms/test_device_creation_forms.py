"""Tests for device creation forms."""

from typing import Any

import pytest
from django import forms

from devices.forms import (
    NoOnboardingCreateForm,
    OnboardingCreateForm,
    OpcUaGdsPushCreateForm,
    OpcUaGdsPushTruststoreAssociationForm,
    OpcUaGdsPushTruststoreMethodSelectForm,
    RevokeIssuedCredentialForm,
    RevokeDevicesForm,
    DeleteDevicesForm,
)
from devices.models import (
    DeviceModel,
    NoOnboardingPkiProtocol,
    OnboardingPkiProtocol,
    OnboardingProtocol,
)


@pytest.mark.django_db
class TestNoOnboardingCreateForm:
    """Tests for NoOnboardingCreateForm."""

    def test_form_initialization(self) -> None:
        """Test NoOnboardingCreateForm initialization."""
        form = NoOnboardingCreateForm()
        
        assert 'common_name' in form.fields
        assert 'serial_number' in form.fields
        assert 'domain' in form.fields
        assert 'no_onboarding_pki_protocols' in form.fields

    def test_form_fields_required(self) -> None:
        """Test which fields are required."""
        form = NoOnboardingCreateForm()
        
        assert form.fields['common_name'].required is True
        assert form.fields['serial_number'].required is False
        assert form.fields['domain'].required is False

    def test_valid_form_data(self, device_instance: dict[str, Any]) -> None:
        """Test form with valid data."""
        domain = device_instance['domain']
        
        form_data = {
            'common_name': 'new-test-device',
            'serial_number': 'SN123456',
            'domain': domain.pk,
            'no_onboarding_pki_protocols': [str(NoOnboardingPkiProtocol.MANUAL.value)],
        }
        
        form = NoOnboardingCreateForm(data=form_data)
        
        assert form.is_valid(), f'Form should be valid, errors: {form.errors}'

    def test_duplicate_common_name(self, device_instance: dict[str, Any]) -> None:
        """Test that duplicate common_name is rejected."""
        device = device_instance['device']
        domain = device_instance['domain']
        
        form_data = {
            'common_name': device.common_name,  # Use existing device's name
            'serial_number': 'SN999999',
            'domain': domain.pk,
            'no_onboarding_pki_protocols': [str(NoOnboardingPkiProtocol.MANUAL.value)],
        }
        
        form = NoOnboardingCreateForm(data=form_data)
        
        assert not form.is_valid()
        assert 'common_name' in form.errors
        assert 'already exists' in str(form.errors['common_name'][0])

    def test_form_without_domain(self) -> None:
        """Test form submission without a domain (domain is optional)."""
        form_data = {
            'common_name': 'device-no-domain',
            'serial_number': 'SN789012',
            'no_onboarding_pki_protocols': [str(NoOnboardingPkiProtocol.MANUAL.value)],
        }
        
        form = NoOnboardingCreateForm(data=form_data)
        
        assert form.is_valid(), f'Form should be valid without domain, errors: {form.errors}'

    def test_multiple_pki_protocols(self, device_instance: dict[str, Any]) -> None:
        """Test form with multiple PKI protocols selected."""
        domain = device_instance['domain']
        
        form_data = {
            'common_name': 'multi-protocol-device',
            'serial_number': 'SN555555',
            'domain': domain.pk,
            'no_onboarding_pki_protocols': [
                str(NoOnboardingPkiProtocol.CMP_SHARED_SECRET.value),
                str(NoOnboardingPkiProtocol.EST_USERNAME_PASSWORD.value),
                str(NoOnboardingPkiProtocol.MANUAL.value),
            ],
        }
        
        form = NoOnboardingCreateForm(data=form_data)
        
        assert form.is_valid(), f'Form should accept multiple protocols, errors: {form.errors}'

    def test_save_creates_device(self, device_instance: dict[str, Any]) -> None:
        """Test that save() method creates a DeviceModel."""
        domain = device_instance['domain']
        
        form_data = {
            'common_name': 'saved-device',
            'serial_number': 'SN111111',
            'domain': domain.pk,
            'no_onboarding_pki_protocols': [str(NoOnboardingPkiProtocol.MANUAL.value)],
        }
        
        form = NoOnboardingCreateForm(data=form_data)
        assert form.is_valid()
        
        device = form.save(device_type=DeviceModel.DeviceType.GENERIC_DEVICE)
        
        assert device.pk is not None
        assert device.common_name == 'saved-device'
        assert device.serial_number == 'SN111111'
        assert device.domain == domain
        assert device.device_type == DeviceModel.DeviceType.GENERIC_DEVICE

    def test_save_with_cmp_shared_secret(self, device_instance: dict[str, Any]) -> None:
        """Test that CMP shared secret is generated when protocol is selected."""
        domain = device_instance['domain']
        
        form_data = {
            'common_name': 'cmp-device',
            'serial_number': 'SN222222',
            'domain': domain.pk,
            'no_onboarding_pki_protocols': [str(NoOnboardingPkiProtocol.CMP_SHARED_SECRET.value)],
        }
        
        form = NoOnboardingCreateForm(data=form_data)
        assert form.is_valid()
        
        device = form.save(device_type=DeviceModel.DeviceType.GENERIC_DEVICE)
        
        assert device.no_onboarding_config is not None
        assert device.no_onboarding_config.cmp_shared_secret is not None
        assert len(device.no_onboarding_config.cmp_shared_secret) > 0

    def test_save_with_est_username_password(self, device_instance: dict[str, Any]) -> None:
        """Test that EST password is generated when protocol is selected."""
        domain = device_instance['domain']
        
        form_data = {
            'common_name': 'est-device',
            'serial_number': 'SN333333',
            'domain': domain.pk,
            'no_onboarding_pki_protocols': [str(NoOnboardingPkiProtocol.EST_USERNAME_PASSWORD.value)],
        }
        
        form = NoOnboardingCreateForm(data=form_data)
        assert form.is_valid()
        
        device = form.save(device_type=DeviceModel.DeviceType.GENERIC_DEVICE)
        
        assert device.no_onboarding_config is not None
        assert device.no_onboarding_config.est_password is not None
        assert len(device.no_onboarding_config.est_password) > 0


@pytest.mark.django_db
class TestOnboardingCreateForm:
    """Tests for OnboardingCreateForm."""

    def test_form_initialization(self) -> None:
        """Test OnboardingCreateForm initialization."""
        form = OnboardingCreateForm()
        
        assert 'common_name' in form.fields
        assert 'serial_number' in form.fields
        assert 'domain' in form.fields
        assert 'onboarding_protocol' in form.fields
        assert 'onboarding_pki_protocols' in form.fields

    def test_valid_form_data(self, device_instance: dict[str, Any]) -> None:
        """Test form with valid onboarding data."""
        domain = device_instance['domain']
        
        # Import OnboardingPkiProtocol for the correct enum
        from onboarding.models import OnboardingPkiProtocol
        
        form_data = {
            'common_name': 'onboarding-device',
            'serial_number': 'SN444444',
            'domain': domain.pk,
            'onboarding_protocol': str(OnboardingProtocol.CMP_SHARED_SECRET.value),
            'onboarding_pki_protocols': [str(OnboardingPkiProtocol.CMP.value)],
        }
        
        form = OnboardingCreateForm(data=form_data)
        
        assert form.is_valid(), f'Form should be valid, errors: {form.errors}'

    def test_duplicate_common_name(self, device_instance: dict[str, Any]) -> None:
        """Test that duplicate common_name is rejected in onboarding form."""
        device = device_instance['device']
        domain = device_instance['domain']
        
        # Import OnboardingPkiProtocol for the correct enum
        from onboarding.models import OnboardingPkiProtocol
        
        form_data = {
            'common_name': device.common_name,  # Duplicate name
            'serial_number': 'SN888888',
            'domain': domain.pk,
            'onboarding_protocol': str(OnboardingProtocol.CMP_SHARED_SECRET.value),
            'onboarding_pki_protocols': [str(OnboardingPkiProtocol.CMP.value)],
        }
        
        form = OnboardingCreateForm(data=form_data)
        
        assert not form.is_valid()
        assert 'common_name' in form.errors

    def test_save_creates_device_with_onboarding(self, device_instance: dict[str, Any]) -> None:
        """Test that save() creates a device with onboarding config."""
        domain = device_instance['domain']
        
        # Import OnboardingPkiProtocol for the correct enum
        from onboarding.models import OnboardingPkiProtocol
        
        form_data = {
            'common_name': 'onboard-saved-device',
            'serial_number': 'SN555555',
            'domain': domain.pk,
            'onboarding_protocol': str(OnboardingProtocol.CMP_SHARED_SECRET.value),
            'onboarding_pki_protocols': [str(OnboardingPkiProtocol.CMP.value)],
        }
        
        form = OnboardingCreateForm(data=form_data)
        assert form.is_valid()
        
        device = form.save(device_type=DeviceModel.DeviceType.GENERIC_DEVICE)
        
        assert device.pk is not None
        assert device.common_name == 'onboard-saved-device'
        assert device.onboarding_config is not None
        assert device.onboarding_config.onboarding_protocol == OnboardingProtocol.CMP_SHARED_SECRET

    def test_save_with_cmp_generates_secret(self, device_instance: dict[str, Any]) -> None:
        """Test that CMP shared secret is generated for onboarding."""
        domain = device_instance['domain']
        
        # Import OnboardingPkiProtocol for the correct enum
        from onboarding.models import OnboardingPkiProtocol
        
        form_data = {
            'common_name': 'cmp-onboard-device',
            'serial_number': 'SN666666',
            'domain': domain.pk,
            'onboarding_protocol': str(OnboardingProtocol.CMP_SHARED_SECRET.value),
            'onboarding_pki_protocols': [str(OnboardingPkiProtocol.CMP.value)],
        }
        
        form = OnboardingCreateForm(data=form_data)
        assert form.is_valid()
        
        device = form.save(device_type=DeviceModel.DeviceType.GENERIC_DEVICE)
        
        assert device.onboarding_config.cmp_shared_secret is not None
        assert len(device.onboarding_config.cmp_shared_secret) > 0

    def test_save_with_est_generates_password(self, device_instance: dict[str, Any]) -> None:
        """Test that EST password is generated for onboarding."""
        domain = device_instance['domain']
        
        # Import OnboardingPkiProtocol for the correct enum
        from onboarding.models import OnboardingPkiProtocol
        
        form_data = {
            'common_name': 'est-onboard-device',
            'serial_number': 'SN777777',
            'domain': domain.pk,
            'onboarding_protocol': str(OnboardingProtocol.EST_USERNAME_PASSWORD.value),
            'onboarding_pki_protocols': [str(OnboardingPkiProtocol.EST.value)],  # Use OnboardingPkiProtocol.EST
        }
        
        form = OnboardingCreateForm(data=form_data)
        assert form.is_valid(), f'Form errors: {form.errors}'
        
        device = form.save(device_type=DeviceModel.DeviceType.GENERIC_DEVICE)
        
        assert device.onboarding_config.est_password is not None
        assert len(device.onboarding_config.est_password) > 0


@pytest.mark.django_db
class TestRevokeIssuedCredentialForm:
    """Tests for RevokeIssuedCredentialForm."""

    def test_form_initialization(self) -> None:
        """Test RevokeIssuedCredentialForm has revocation_reason field."""
        form = RevokeIssuedCredentialForm()
        
        assert 'revocation_reason' in form.fields
        # It's a ModelForm, so it doesn't have pk field in fields dict

    def test_form_is_modelform(self) -> None:
        """Test that RevokeIssuedCredentialForm is a ModelForm."""
        form = RevokeIssuedCredentialForm()
        
        assert hasattr(form, 'Meta')
        assert hasattr(form.Meta, 'model')
        assert hasattr(form.Meta, 'fields')


@pytest.mark.django_db
class TestRevokeDevicesForm:
    """Tests for RevokeDevicesForm."""

    def test_form_initialization(self) -> None:
        """Test RevokeDevicesForm has pks and revocation_reason fields."""
        form = RevokeDevicesForm()
        
        assert 'pks' in form.fields
        assert 'revocation_reason' in form.fields
        assert isinstance(form.fields['pks'].widget, forms.HiddenInput)


@pytest.mark.django_db
class TestDeleteDevicesForm:
    """Tests for DeleteDevicesForm."""

    def test_form_initialization(self) -> None:
        """Test DeleteDevicesForm has pks field."""
        form = DeleteDevicesForm()
        
        assert 'pks' in form.fields
        assert isinstance(form.fields['pks'].widget, forms.HiddenInput)

    def test_form_with_data(self) -> None:
        """Test DeleteDevicesForm with sample data."""
        form_data = {
            'pks': '1,2,3,4,5',
        }
        
        form = DeleteDevicesForm(data=form_data)
        
        assert form.is_valid()
        assert form.cleaned_data['pks'] == '1,2,3,4,5'


@pytest.mark.django_db
class TestOpcUaGdsPushCreateForm:
    """Tests for OpcUaGdsPushCreateForm."""

    def test_form_initialization(self) -> None:
        """Test OpcUaGdsPushCreateForm initialization."""
        form = OpcUaGdsPushCreateForm()

        assert 'common_name' in form.fields
        assert 'serial_number' in form.fields
        assert 'domain' in form.fields
        assert 'ip_address' in form.fields
        assert 'opc_server_port' in form.fields
        assert 'opc_user' in form.fields
        assert 'opc_password' in form.fields

    def test_form_fields_required(self) -> None:
        """Test which fields are required."""
        form = OpcUaGdsPushCreateForm()

        assert form.fields['common_name'].required is True
        assert form.fields['serial_number'].required is False
        assert form.fields['domain'].required is False
        assert form.fields['ip_address'].required is True
        assert form.fields['opc_server_port'].required is True
        assert form.fields['opc_user'].required is False
        assert form.fields['opc_password'].required is False

    def test_valid_form_data(self, device_instance: dict[str, Any]) -> None:
        """Test form with valid data."""
        domain = device_instance['domain']

        form_data = {
            'common_name': 'new-gds-push-device',
            'serial_number': 'SN123456',
            'domain': domain.pk,
            'ip_address': '192.168.1.100',
            'opc_server_port': 4840,
            'opc_user': 'admin',
            'opc_password': 'secret123',
        }

        form = OpcUaGdsPushCreateForm(data=form_data)
        assert form.is_valid()

        device = form.save(DeviceModel.DeviceType.OPC_UA_GDS_PUSH)
        assert device.common_name == 'new-gds-push-device'
        assert device.serial_number == 'SN123456'
        assert device.domain == domain
        assert device.ip_address == '192.168.1.100'
        assert device.opc_server_port == 4840
        assert device.device_type == DeviceModel.DeviceType.OPC_UA_GDS_PUSH
        assert device.onboarding_config is not None
        assert device.onboarding_config.onboarding_protocol == OnboardingProtocol.OPC_GDS_PUSH
        assert device.onboarding_config.opc_user == 'admin'
        assert device.onboarding_config.opc_password == 'secret123'
        assert device.onboarding_config.has_pki_protocol(OnboardingPkiProtocol.OPC_GDS_PUSH)

    def test_duplicate_common_name_validation(self, device_instance: dict[str, Any]) -> None:
        """Test that duplicate common names are rejected."""
        existing_device = device_instance['device']

        form_data = {
            'common_name': existing_device.common_name,  # Duplicate name
            'ip_address': '192.168.1.100',
            'opc_server_port': 4840,
        }

        form = OpcUaGdsPushCreateForm(data=form_data)
        assert not form.is_valid()
        assert 'common_name' in form.errors
        assert 'Device with this common name already exists' in str(form.errors['common_name'])

    def test_invalid_ip_address(self) -> None:
        """Test form with invalid IP address."""
        form_data = {
            'common_name': 'test-device',
            'ip_address': 'invalid-ip',
            'opc_server_port': 4840,
        }

        form = OpcUaGdsPushCreateForm(data=form_data)
        assert not form.is_valid()
        assert 'ip_address' in form.errors

    def test_invalid_port_range(self) -> None:
        """Test form with invalid port numbers."""
        # Test port too low
        form_data = {
            'common_name': 'test-device',
            'ip_address': '192.168.1.100',
            'opc_server_port': 0,
        }

        form = OpcUaGdsPushCreateForm(data=form_data)
        assert not form.is_valid()
        assert 'opc_server_port' in form.errors

        # Test port too high
        form_data['opc_server_port'] = 70000
        form = OpcUaGdsPushCreateForm(data=form_data)
        assert not form.is_valid()
        assert 'opc_server_port' in form.errors


@pytest.mark.django_db
class TestOpcUaGdsPushTruststoreAssociationForm:
    """Tests for OpcUaGdsPushTruststoreAssociationForm."""

    def test_form_initialization(self, device_instance_onboarding: dict[str, Any]) -> None:
        """Test form initialization with device instance."""
        device = device_instance_onboarding['device']

        form = OpcUaGdsPushTruststoreAssociationForm(instance=device)

        assert form.instance == device
        assert 'opc_trust_store' in form.fields
        assert form.fields['opc_trust_store'].required is True

    def test_save_associates_truststore(self, device_instance_onboarding: dict[str, Any]) -> None:
        """Test that save() associates the truststore with the device."""
        device = device_instance_onboarding['device']
        
        # Create a mock truststore
        from pki.models.truststore import TruststoreModel
        truststore = TruststoreModel.objects.create(
            unique_name='test-truststore',
            intended_usage=TruststoreModel.IntendedUsage.OPC_UA_GDS_PUSH
        )

        form_data = {
            'opc_trust_store': truststore.pk,
        }

        form = OpcUaGdsPushTruststoreAssociationForm(data=form_data, instance=device)
        assert form.is_valid()

        form.save()

        device.refresh_from_db()
        assert device.onboarding_config.opc_trust_store == truststore


class TestOpcUaGdsPushTruststoreMethodSelectForm:
    """Tests for OpcUaGdsPushTruststoreMethodSelectForm."""

    def test_form_initialization(self) -> None:
        """Test form initialization."""
        form = OpcUaGdsPushTruststoreMethodSelectForm()

        assert 'method_select' in form.fields
        assert form.fields['method_select'].required is True
        assert form.fields['method_select'].initial == 'select_truststore'

    def test_form_choices(self) -> None:
        """Test that form has correct choices."""
        form = OpcUaGdsPushTruststoreMethodSelectForm()

        expected_choices = [
            ('upload_truststore', 'Upload a new truststore prior to association'),
            ('select_truststore', 'Use an existing truststore for association'),
        ]

        assert list(form.fields['method_select'].choices) == expected_choices

    def test_valid_form_data(self) -> None:
        """Test form with valid data."""
        form_data = {
            'method_select': 'upload_truststore',
        }

        form = OpcUaGdsPushTruststoreMethodSelectForm(data=form_data)
        assert form.is_valid()
        assert form.cleaned_data['method_select'] == 'upload_truststore'

    def test_invalid_choice(self) -> None:
        """Test form with invalid choice."""
        form_data = {
            'method_select': 'invalid_choice',
        }

        form = OpcUaGdsPushTruststoreMethodSelectForm(data=form_data)
        assert not form.is_valid()
        assert 'method_select' in form.errors
