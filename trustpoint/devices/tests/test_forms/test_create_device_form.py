"""Test suite for validating the CreateDeviceForm."""

from typing import Any

import pytest

from devices.forms import NoOnboardingCreateForm
from devices.models import DeviceModel, OnboardingStatus


@pytest.mark.django_db
def test_create_device_form_valid_data(domain_instance: dict[str, Any]) -> None:
    """Test CreateDeviceForm with valid data."""
    domain = domain_instance['domain']

    form_data = {
        'common_name': 'TestDevice',
        'serial_number': '12345',
        'domain': domain.pk,
        'domain_credential_onboarding': True,
        'onboarding_and_pki_configuration': 'cmp_shared_secret',
        'pki_configuration': 'cmp_shared_secret',
    }

    form = NoOnboardingCreateForm(data=form_data)

    assert form.is_valid(), f'Form should be valid, but errors were found: {form.errors}'

    device = form.save(commit=False)
    assert device.common_name == 'TestDevice', 'Device common name should match input'
    assert device.serial_number == '12345', 'Serial number should match input'
    assert device.domain == domain, 'Device domain should match the domain instance'
    assert device.no_onboarding_config.onboarding_status == OnboardingStatus.PENDING, 'Onboarding status should be PENDING'
    assert device.no_onboarding_config.cmp_shared_secret, 'CMP shared secret should be auto-generated'
