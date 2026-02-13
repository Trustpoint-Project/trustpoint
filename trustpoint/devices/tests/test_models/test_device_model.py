"""Tests for the DeviceModel model."""

from typing import Any

import pytest
from django.db import IntegrityError

from devices.models import (
    DeviceModel,
    OnboardingConfigModel,
    OnboardingProtocol,
    OnboardingPkiProtocol,
    NoOnboardingConfigModel,
    NoOnboardingPkiProtocol,
    OnboardingStatus,
)


@pytest.mark.django_db
def test_no_onboarding_with_est_password(domain_instance: dict[str, Any]) -> None:
    """Test for no onboarding configuration with EST Password PKI protocol."""
    domain = domain_instance['domain']

    no_onboarding_config = NoOnboardingConfigModel(est_password='test_est_password')  # noqa: S106
    no_onboarding_config.add_pki_protocol(NoOnboardingPkiProtocol.EST_USERNAME_PASSWORD)
    no_onboarding_config.full_clean()
    no_onboarding_config.save()

    device = DeviceModel.objects.create(
        common_name='NoOnboarding_EST',
        serial_number='SN_NO_EST',
        domain=domain,
        no_onboarding_config=no_onboarding_config,
    )

    # Assertions
    assert device.id is not None
    assert device.common_name == 'NoOnboarding_EST'
    assert device.no_onboarding_config.get_pki_protocols() == [NoOnboardingPkiProtocol.EST_USERNAME_PASSWORD]
    assert device.no_onboarding_config.est_password == 'test_est_password'  # noqa: S105


@pytest.mark.django_db
def test_no_onboarding_with_cmp_shared_secret(domain_instance: dict[str, Any]) -> None:
    """Test for no onboarding configuration with CMP Shared Secret PKI protocol."""
    domain = domain_instance['domain']

    no_onboarding_config = NoOnboardingConfigModel(cmp_shared_secret='test_cmp_secret')  # noqa: S106
    no_onboarding_config.add_pki_protocol(NoOnboardingPkiProtocol.CMP_SHARED_SECRET)
    no_onboarding_config.full_clean()
    no_onboarding_config.save()

    device = DeviceModel.objects.create(
        common_name='NoOnboarding_CMP',
        serial_number='SN_NO_CMP',
        domain=domain,
        no_onboarding_config=no_onboarding_config,
    )

    # Assertions
    assert device.id is not None
    assert device.common_name == 'NoOnboarding_CMP'
    assert device.no_onboarding_config.get_pki_protocols() == [NoOnboardingPkiProtocol.CMP_SHARED_SECRET]
    assert device.no_onboarding_config.cmp_shared_secret == 'test_cmp_secret'  # noqa: S105


@pytest.mark.django_db
def test_est_onboarding_with_client_certificate(domain_instance: dict[str, Any]) -> None:
    """Test for EST onboarding configuration with EST Client Certificate PKI protocol."""
    domain = domain_instance['domain']

    onboarding_pki_protocols = [OnboardingPkiProtocol.EST]
    onboarding_config_model = OnboardingConfigModel(onboarding_protocol=OnboardingProtocol.EST_IDEVID)
    onboarding_config_model.set_pki_protocols(onboarding_pki_protocols)

    onboarding_config_model.full_clean()
    onboarding_config_model.save()

    device = DeviceModel.objects.create(
        common_name='EST_Onboarding',
        serial_number='SN_EST_ONBOARD',
        domain=domain,
        onboarding_config=onboarding_config_model,
    )

    # Assertions
    assert device.id is not None
    assert device.common_name == 'EST_Onboarding'
    assert device.onboarding_config.onboarding_status == OnboardingStatus.PENDING
    assert device.onboarding_config.onboarding_protocol == OnboardingProtocol.EST_IDEVID
    assert device.onboarding_config.get_pki_protocols() == [OnboardingPkiProtocol.EST]


@pytest.mark.django_db
def test_cmp_onboarding_with_client_certificate(domain_instance: dict[str, Any]) -> None:
    """Test for CMP onboarding configuration with CMP Client Certificate PKI protocol."""
    domain = domain_instance['domain']

    onboarding_pki_protocols = [OnboardingPkiProtocol.CMP]
    onboarding_config_model = OnboardingConfigModel(onboarding_protocol=OnboardingProtocol.CMP_IDEVID)
    onboarding_config_model.set_pki_protocols(onboarding_pki_protocols)

    onboarding_config_model.full_clean()
    onboarding_config_model.save()

    device = DeviceModel.objects.create(
        common_name='CMP_Onboarding',
        serial_number='SN_CMP_ONBOARD',
        domain=domain,
        onboarding_config=onboarding_config_model,
    )

    # Assertions
    assert device.id is not None
    assert device.common_name == 'CMP_Onboarding'
    assert device.onboarding_config.onboarding_status == OnboardingStatus.PENDING
    assert device.onboarding_config.onboarding_protocol == OnboardingProtocol.CMP_IDEVID
    assert device.onboarding_config.get_pki_protocols() == [OnboardingPkiProtocol.CMP]


@pytest.mark.django_db
def test_generic_device_no_onboarding(domain_instance: dict[str, Any]) -> None:
    """Test for a generic device with no onboarding configurations."""
    domain = domain_instance['domain']

    no_onboarding_config = NoOnboardingConfigModel()
    no_onboarding_config.add_pki_protocol(NoOnboardingPkiProtocol.MANUAL)
    no_onboarding_config.full_clean()
    no_onboarding_config.save()

    device = DeviceModel.objects.create(
        common_name='GenericDevice_NoOnboarding',
        serial_number='GENERIC_NO_ONBOARD',
        domain=domain,
        no_onboarding_config=no_onboarding_config,
    )

    # Assertions
    assert device.id is not None
    assert device.common_name == 'GenericDevice_NoOnboarding'
    assert device.no_onboarding_config.get_pki_protocols() == [NoOnboardingPkiProtocol.MANUAL]
    assert device.no_onboarding_config.est_password == ''


@pytest.mark.django_db
def test_device_opc_ua_gds(domain_instance: dict[str, Any]) -> None:
    """Test for a device with OPC UA GDS type."""
    domain = domain_instance['domain']

    onboarding_pki_protocols = [OnboardingPkiProtocol.EST]
    onboarding_config_model = OnboardingConfigModel(onboarding_protocol=OnboardingProtocol.EST_IDEVID)
    onboarding_config_model.set_pki_protocols(onboarding_pki_protocols)

    onboarding_config_model.full_clean()
    onboarding_config_model.save()

    device = DeviceModel.objects.create(
        common_name='OPCUA_Device',
        serial_number='SN_OPCUA',
        domain=domain,
        device_type=DeviceModel.DeviceType.OPC_UA_GDS,
        onboarding_config=onboarding_config_model,
    )

    # Assertions
    assert device.id is not None
    assert device.common_name == 'OPCUA_Device'
    assert device.serial_number == 'SN_OPCUA'
    assert device.device_type == DeviceModel.DeviceType.OPC_UA_GDS
    assert device.onboarding_config.onboarding_status == OnboardingStatus.PENDING
    assert device.onboarding_config.onboarding_protocol == OnboardingProtocol.EST_IDEVID
    assert device.onboarding_config.get_pki_protocols() == [OnboardingPkiProtocol.EST]


@pytest.mark.django_db
def test_device_without_domain() -> None:
    """Test for a device with no assigned domain."""
    device = DeviceModel.objects.create(
        common_name='NoDomain_Device',
        serial_number='NO_DOMAIN',
        domain=None,
    )

    # Assertions
    assert device.id is not None
    assert device.common_name == 'NoDomain_Device'
    assert device.serial_number == 'NO_DOMAIN'
    assert device.domain is None


@pytest.mark.django_db
def test_device_creation_without_common_name(domain_instance: dict[str, Any]) -> None:
    """Test for device creation without a common name."""
    domain = domain_instance['domain']

    with pytest.raises(
        IntegrityError,
        match=r'(null value in column "common_name" of relation "devices_devicemodel" violates not-null constraint|NOT NULL constraint failed: devices_devicemodel\.common_name)',
    ):
        DeviceModel.objects.create(
            common_name=None,  # type: ignore[misc]
            serial_number='MISSING_COMMON_NAME',
            domain=domain,
        )
