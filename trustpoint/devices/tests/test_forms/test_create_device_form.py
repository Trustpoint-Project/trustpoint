"""Test suite for validating the CreateDeviceForm."""

from typing import Any

import pytest

from devices.forms import NoOnboardingCreateForm
from devices.models import DeviceModel

@pytest.mark.django_db
def test_create_device_form_valid_data(domain_instance: dict[str, Any]) -> None:
    """Test CreateDeviceForm with valid data."""
    domain = domain_instance['domain']

    form_data = {
        'common_name': 'TestDevice',
        'serial_number': '12345',
        'domain': domain.pk,
        'no_onboarding_pki_protocols': [1],  # 1 is CMP Shared Secret
    }

    form = NoOnboardingCreateForm(data=form_data)

    assert form.is_valid(), f'Form should be valid, but errors were found: {form.errors}'

    device = form.save(device_type=DeviceModel.DeviceType.GENERIC_DEVICE)
    assert device.common_name == 'TestDevice', 'Device common name should match input'
    assert device.serial_number == '12345', 'Serial number should match input'
    assert device.domain == domain, 'Device domain should match the domain instance'
    assert device.no_onboarding_config.cmp_shared_secret, 'CMP shared secret should be auto-generated'


@pytest.mark.django_db
def test_create_device_form_invalid_common_name_characters(domain_instance: dict[str, Any]) -> None:
    """Test CreateDeviceForm rejects invalid common name characters."""
    domain = domain_instance['domain']

    invalid_names = [
        'device@example.com',
        'http://evil.com',
    ]

    for invalid_name in invalid_names:
        form_data = {
            'common_name': invalid_name,
            'serial_number': '12345',
            'domain': domain.pk,
            'no_onboarding_pki_protocols': [1],
        }

        form = NoOnboardingCreateForm(data=form_data)

        assert not form.is_valid(), f'Form should reject invalid common name: {invalid_name}'
        assert 'common_name' in form.errors


@pytest.mark.django_db
def test_create_device_form_duplicate_common_name(domain_instance: dict[str, Any]) -> None:
    """Test CreateDeviceForm rejects duplicate common names."""
    domain = domain_instance['domain']

    # Create first device
    form_data1 = {
        'common_name': 'TestDevice',
        'serial_number': '12345',
        'domain': domain.pk,
        'no_onboarding_pki_protocols': [1],
    }

    form1 = NoOnboardingCreateForm(data=form_data1)
    assert form1.is_valid()
    form1.save(device_type=DeviceModel.DeviceType.GENERIC_DEVICE)

    # Try to create second device with same name
    form_data2 = {
        'common_name': 'TestDevice',  # Same name
        'serial_number': '67890',
        'domain': domain.pk,
        'no_onboarding_pki_protocols': [1],
    }

    form2 = NoOnboardingCreateForm(data=form_data2)
    assert not form2.is_valid()
    assert 'common_name' in form2.errors
