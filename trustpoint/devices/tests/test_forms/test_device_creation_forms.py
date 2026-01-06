"""Tests for device creation forms."""

from typing import Any

import pytest
from django import forms

from devices.forms import (
    NoOnboardingCreateForm,
    OnboardingCreateForm,
    RevokeIssuedCredentialForm,
    RevokeDevicesForm,
    DeleteDevicesForm,
)
from devices.models import (
    DeviceModel,
    NoOnboardingPkiProtocol,
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
        from devices.models import OnboardingPkiProtocol
        
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
        from devices.models import OnboardingPkiProtocol
        
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
        from devices.models import OnboardingPkiProtocol
        
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
        from devices.models import OnboardingPkiProtocol
        
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
        from devices.models import OnboardingPkiProtocol
        
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
