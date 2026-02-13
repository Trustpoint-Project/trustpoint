"""Tests for Certificate Lifecycle Management (CLM) Device forms."""

from typing import Any

import pytest
from django.forms import ValidationError

from devices.forms import ClmDeviceModelNoOnboardingForm, ClmDeviceModelOnboardingForm
from devices.models import (
    DeviceModel,
    NoOnboardingPkiProtocol,
    OnboardingPkiProtocol,
    OnboardingProtocol,
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

    def test_save_with_manual_onboarding_clears_secrets(self, device_instance_onboarding: dict[str, Any]) -> None:
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

    def test_save_with_cmp_generates_shared_secret(self, device_instance_onboarding: dict[str, Any]) -> None:
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

    def test_save_with_est_generates_password(self, device_instance_onboarding: dict[str, Any]) -> None:
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

    def test_save_updates_pki_protocols_cmp_only(self, device_instance_onboarding: dict[str, Any]) -> None:
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

    def test_save_updates_pki_protocols_est_only(self, device_instance_onboarding: dict[str, Any]) -> None:
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

    def test_save_updates_pki_protocols_both(self, device_instance_onboarding: dict[str, Any]) -> None:
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

    def test_save_without_onboarding_config_raises_error(self, device_instance: dict[str, Any]) -> None:
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

    def test_save_with_cmp_protocol_generates_secret(self, device_instance: dict[str, Any]) -> None:
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

    def test_save_without_cmp_clears_secret(self, device_instance: dict[str, Any]) -> None:
        """Test save() clears CMP shared secret when protocol is disabled."""
        device = device_instance['device']
        domain = device_instance['domain']

        # Set a secret first
        device.no_onboarding_config.cmp_shared_secret = 'test_secret'
        device.no_onboarding_config.save()

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

    def test_save_with_est_protocol_generates_password(self, device_instance: dict[str, Any]) -> None:
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

    def test_save_without_est_clears_password(self, device_instance: dict[str, Any]) -> None:
        """Test save() clears EST password when protocol is disabled."""
        device = device_instance['device']
        domain = device_instance['domain']

        # Set a password first
        device.no_onboarding_config.est_password = 'test_password'
        device.no_onboarding_config.save()

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

    def test_save_with_manual_protocol(self, device_instance: dict[str, Any]) -> None:
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

    def test_save_with_all_protocols(self, device_instance: dict[str, Any]) -> None:
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

    def test_save_without_no_onboarding_config_raises_error(self, device_instance_onboarding: dict[str, Any]) -> None:
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
