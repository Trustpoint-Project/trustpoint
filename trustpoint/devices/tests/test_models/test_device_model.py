"""Tests for the DeviceModel model."""
from typing import Any

import pytest
from django.db import IntegrityError

from devices.models import DeviceModel


@pytest.mark.django_db
def test_no_onboarding_with_est_password(domain_instance: dict[str, Any]) -> None:
    """Test for no onboarding configuration with EST Password PKI protocol."""
    domain = domain_instance['domain']

    device = DeviceModel.objects.create(
        common_name='NoOnboarding_EST',
        serial_number='SN_NO_EST',
        domain=domain,
        onboarding_status=DeviceModel.OnboardingStatus.NO_ONBOARDING,
        onboarding_protocol=DeviceModel.OnboardingProtocol.NO_ONBOARDING,
        pki_protocol=DeviceModel.PkiProtocol.EST_PASSWORD,
        est_password='test_est_password',   # noqa: S106
    )

    # Assertions
    assert device.id is not None
    assert device.common_name == 'NoOnboarding_EST'
    assert device.onboarding_status == DeviceModel.OnboardingStatus.NO_ONBOARDING
    assert device.onboarding_protocol == DeviceModel.OnboardingProtocol.NO_ONBOARDING
    assert device.pki_protocol == DeviceModel.PkiProtocol.EST_PASSWORD
    assert device.est_password == 'test_est_password'   # noqa: S105


@pytest.mark.django_db
def test_no_onboarding_with_cmp_shared_secret(domain_instance: dict[str, Any]) -> None:
    """Test for no onboarding configuration with CMP Shared Secret PKI protocol."""
    domain = domain_instance['domain']

    device = DeviceModel.objects.create(
        common_name='NoOnboarding_CMP',
        serial_number='SN_NO_CMP',
        domain=domain,
        onboarding_status=DeviceModel.OnboardingStatus.NO_ONBOARDING,
        onboarding_protocol=DeviceModel.OnboardingProtocol.NO_ONBOARDING,
        pki_protocol=DeviceModel.PkiProtocol.CMP_SHARED_SECRET,
        cmp_shared_secret='test_cmp_secret',    # noqa: S106
    )

    # Assertions
    assert device.id is not None
    assert device.common_name == 'NoOnboarding_CMP'
    assert device.onboarding_status == DeviceModel.OnboardingStatus.NO_ONBOARDING
    assert device.onboarding_protocol == DeviceModel.OnboardingProtocol.NO_ONBOARDING
    assert device.pki_protocol == DeviceModel.PkiProtocol.CMP_SHARED_SECRET
    assert device.cmp_shared_secret == 'test_cmp_secret'    # noqa: S105


@pytest.mark.django_db
def test_est_onboarding_with_client_certificate(domain_instance: dict[str, Any]) -> None:
    """Test for EST onboarding configuration with EST Client Certificate PKI protocol."""
    domain = domain_instance['domain']

    device = DeviceModel.objects.create(
        common_name='EST_Onboarding',
        serial_number='SN_EST_ONBOARD',
        domain=domain,
        onboarding_status=DeviceModel.OnboardingStatus.PENDING,
        onboarding_protocol=DeviceModel.OnboardingProtocol.EST_PASSWORD,
        pki_protocol=DeviceModel.PkiProtocol.EST_CLIENT_CERTIFICATE,
    )

    # Assertions
    assert device.id is not None
    assert device.common_name == 'EST_Onboarding'
    assert device.onboarding_status == DeviceModel.OnboardingStatus.PENDING
    assert device.onboarding_protocol == DeviceModel.OnboardingProtocol.EST_PASSWORD
    assert device.pki_protocol == DeviceModel.PkiProtocol.EST_CLIENT_CERTIFICATE


@pytest.mark.django_db
def test_cmp_onboarding_with_client_certificate(domain_instance: dict[str, Any]) -> None:
    """Test for CMP onboarding configuration with CMP Client Certificate PKI protocol."""
    domain = domain_instance['domain']

    device = DeviceModel.objects.create(
        common_name='CMP_Onboarding',
        serial_number='SN_CMP_ONBOARD',
        domain=domain,
        onboarding_status=DeviceModel.OnboardingStatus.PENDING,
        onboarding_protocol=DeviceModel.OnboardingProtocol.CMP_SHARED_SECRET,
        pki_protocol=DeviceModel.PkiProtocol.CMP_CLIENT_CERTIFICATE,
    )

    # Assertions
    assert device.id is not None
    assert device.common_name == 'CMP_Onboarding'
    assert device.onboarding_status == DeviceModel.OnboardingStatus.PENDING
    assert device.onboarding_protocol == DeviceModel.OnboardingProtocol.CMP_SHARED_SECRET
    assert device.pki_protocol == DeviceModel.PkiProtocol.CMP_CLIENT_CERTIFICATE

@pytest.mark.django_db
def test_generic_device_no_onboarding(domain_instance: dict[str, Any]) -> None:
    """Test for a generic device with no onboarding configurations."""
    domain = domain_instance['domain']

    device = DeviceModel.objects.create(
        common_name='GenericDevice_NoOnboarding',
        serial_number='GENERIC_NO_ONBOARD',
        domain=domain,
        onboarding_status=DeviceModel.OnboardingStatus.NO_ONBOARDING,
        onboarding_protocol=DeviceModel.OnboardingProtocol.NO_ONBOARDING,
        pki_protocol=DeviceModel.PkiProtocol.MANUAL,
    )

    # Assertions
    assert device.id is not None
    assert device.common_name == 'GenericDevice_NoOnboarding'
    assert device.onboarding_status == DeviceModel.OnboardingStatus.NO_ONBOARDING
    assert device.onboarding_protocol == DeviceModel.OnboardingProtocol.NO_ONBOARDING
    assert device.pki_protocol == DeviceModel.PkiProtocol.MANUAL

@pytest.mark.django_db
def test_device_opcua_gds(domain_instance: dict[str, Any]) -> None:
    """Test for a device with OPC UA GDS type."""
    domain = domain_instance['domain']

    device = DeviceModel.objects.create(
        common_name='OPCUA_Device',
        serial_number='SN_OPCUA',
        domain=domain,
        onboarding_status=DeviceModel.OnboardingStatus.PENDING,
        device_type=DeviceModel.DeviceType.OPC_UA_GDS,
        pki_protocol=DeviceModel.PkiProtocol.EST_CLIENT_CERTIFICATE,
    )

    # Assertions
    assert device.id is not None
    assert device.common_name == 'OPCUA_Device'
    assert device.serial_number == 'SN_OPCUA'
    assert device.onboarding_status == DeviceModel.OnboardingStatus.PENDING
    assert device.device_type == DeviceModel.DeviceType.OPC_UA_GDS
    assert device.pki_protocol == DeviceModel.PkiProtocol.EST_CLIENT_CERTIFICATE


@pytest.mark.django_db
def test_device_without_domain() -> None:
    """Test for a device with no assigned domain."""
    device = DeviceModel.objects.create(
        common_name='NoDomain_Device',
        serial_number='NO_DOMAIN',
        domain=None,
        onboarding_status=DeviceModel.OnboardingStatus.NO_ONBOARDING,
        onboarding_protocol=DeviceModel.OnboardingProtocol.NO_ONBOARDING,
        pki_protocol=DeviceModel.PkiProtocol.MANUAL,
    )

    # Assertions
    assert device.id is not None
    assert device.common_name == 'NoDomain_Device'
    assert device.serial_number == 'NO_DOMAIN'
    assert device.onboarding_status == DeviceModel.OnboardingStatus.NO_ONBOARDING
    assert device.onboarding_protocol == DeviceModel.OnboardingProtocol.NO_ONBOARDING
    assert device.pki_protocol == DeviceModel.PkiProtocol.MANUAL
    assert device.domain is None

@pytest.mark.django_db
def test_device_creation_without_common_name(domain_instance: dict[str, Any]) -> None:
    """Test for device creation without a common name."""
    domain = domain_instance['domain']

    with pytest.raises(IntegrityError, match='NOT NULL constraint failed: devices_devicemodel.common_name'):
        DeviceModel.objects.create(
            common_name=None,   # type: ignore[misc]
            serial_number='MISSING_COMMON_NAME',
            domain=domain,
            onboarding_status=DeviceModel.OnboardingStatus.NO_ONBOARDING,
            onboarding_protocol=DeviceModel.OnboardingProtocol.NO_ONBOARDING,
            pki_protocol=DeviceModel.PkiProtocol.MANUAL,
        )

