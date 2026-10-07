# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Device-management Behave steps."""

from __future__ import annotations

import uuid

from behave import given, runner, then, when
from devices.models import DeviceModel
from onboarding.models import NoOnboardingPkiProtocol
from pki.models import DomainModel

from features.support.factories import create_no_onboarding_device


_PROTOCOLS_BY_NAME: dict[str, NoOnboardingPkiProtocol] = {
    "CMP_SHARED_SECRET": NoOnboardingPkiProtocol.CMP_SHARED_SECRET,
    "EST_USERNAME_PASSWORD": NoOnboardingPkiProtocol.EST_USERNAME_PASSWORD,
    "MANUAL": NoOnboardingPkiProtocol.MANUAL,
    "REST_USERNAME_PASSWORD": NoOnboardingPkiProtocol.REST_USERNAME_PASSWORD,
}


def _protocol_from_name(protocol_name: str) -> NoOnboardingPkiProtocol:
    """Return the no-onboarding protocol for a Gherkin protocol name."""
    try:
        return _PROTOCOLS_BY_NAME[protocol_name]
    except KeyError as exc:
        supported = ", ".join(sorted(_PROTOCOLS_BY_NAME))
        msg = f'Unsupported no-onboarding PKI protocol "{protocol_name}". Supported: {supported}.'
        raise AssertionError(msg) from exc


def _post_no_onboarding_device(
    context: runner.Context,
    *,
    name: str,
    serial_number: str = "",
    domain: DomainModel | None = None,
    protocols: list[NoOnboardingPkiProtocol] | None = None,
) -> None:
    """Create a generic no-onboarding device through the public Django view."""
    selected_protocols = protocols or [NoOnboardingPkiProtocol.MANUAL]
    data: dict[str, object] = {
        "common_name": name,
        "serial_number": serial_number,
        "no_onboarding_pki_protocols": [str(protocol.value) for protocol in selected_protocols],
    }
    if domain is not None:
        data["domain"] = domain.pk

    context.response = context.authenticated_client.post(
        "/devices/create/no-onboarding/",
        data,
        follow=True,
    )


@given('a domain named "{domain_name}" exists')
def step_domain_exists(context: runner.Context, domain_name: str) -> None:
    """Ensure an active domain exists."""
    context.domain, _ = DomainModel.objects.get_or_create(
        unique_name=domain_name,
        defaults={"is_active": True},
    )
    if not context.domain.is_active:
        context.domain.is_active = True
        context.domain.save(update_fields=["is_active"])


@when(
    'the admin creates a no-onboarding device named "{name}" '
    'with serial number "{serial}" in domain "{domain_name}"'
)
def step_create_device(
    context: runner.Context,
    name: str,
    serial: str,
    domain_name: str,
) -> None:
    """Create a no-onboarding device with a serial number and domain."""
    domain = DomainModel.objects.get(unique_name=domain_name)
    _post_no_onboarding_device(
        context,
        name=name,
        serial_number=serial,
        domain=domain,
        protocols=[NoOnboardingPkiProtocol.MANUAL],
    )


@when(
    'the admin creates a no-onboarding device named "{name}" '
    'with serial number "{serial}" without a domain'
)
def step_create_device_without_domain(
    context: runner.Context,
    name: str,
    serial: str,
) -> None:
    """Create a no-onboarding device without assigning a domain."""
    _post_no_onboarding_device(
        context,
        name=name,
        serial_number=serial,
        protocols=[NoOnboardingPkiProtocol.MANUAL],
    )


@when(
    'the admin creates a no-onboarding device named "{name}" '
    'without a serial number in domain "{domain_name}"'
)
def step_create_device_without_serial(
    context: runner.Context,
    name: str,
    domain_name: str,
) -> None:
    """Create a no-onboarding device without a serial number."""
    domain = DomainModel.objects.get(unique_name=domain_name)
    _post_no_onboarding_device(
        context,
        name=name,
        domain=domain,
        protocols=[NoOnboardingPkiProtocol.MANUAL],
    )


@when(
    'the admin creates a no-onboarding device named "{name}" '
    'using PKI protocol "{protocol_name}" in domain "{domain_name}"'
)
def step_create_device_with_protocol(
    context: runner.Context,
    name: str,
    protocol_name: str,
    domain_name: str,
) -> None:
    """Create a no-onboarding device with one selected PKI protocol."""
    domain = DomainModel.objects.get(unique_name=domain_name)
    protocol = _protocol_from_name(protocol_name)
    _post_no_onboarding_device(
        context,
        name=name,
        domain=domain,
        protocols=[protocol],
    )


@when(
    'the admin creates a no-onboarding device named "{name}" '
    'with the following PKI protocols in domain "{domain_name}":'
)
def step_create_device_with_protocol_table(
    context: runner.Context,
    name: str,
    domain_name: str,
) -> None:
    """Create a no-onboarding device with protocols supplied as a Gherkin table."""
    assert context.table is not None, "Expected a protocol table."
    protocol_names = [row["protocol"].strip() for row in context.table]
    assert protocol_names, "At least one protocol must be supplied."

    protocols = [_protocol_from_name(protocol_name) for protocol_name in protocol_names]
    domain = DomainModel.objects.get(unique_name=domain_name)
    _post_no_onboarding_device(
        context,
        name=name,
        domain=domain,
        protocols=protocols,
    )


@when(
    'the admin attempts to create another no-onboarding device named "{name}" '
    'in domain "{domain_name}"'
)
def step_attempt_duplicate_device(
    context: runner.Context,
    name: str,
    domain_name: str,
) -> None:
    """Attempt to create a duplicate device through the public creation view."""
    domain = DomainModel.objects.get(unique_name=domain_name)
    _post_no_onboarding_device(
        context,
        name=name,
        domain=domain,
        protocols=[NoOnboardingPkiProtocol.MANUAL],
    )


@then('a device named "{name}" with serial number "{serial}" exists')
def step_device_created(context: runner.Context, name: str, serial: str) -> None:
    """Assert a device exists with the expected serial number."""
    device = DeviceModel.objects.get(common_name=name)
    assert device.serial_number == serial, (
        f'Expected serial number "{serial}" for device "{name}", '
        f'got "{device.serial_number}".'
    )
    context.device = device


@then('a device named "{name}" exists')
def step_device_exists(context: runner.Context, name: str) -> None:
    """Assert a device exists."""
    context.device = DeviceModel.objects.get(common_name=name)


@then('the device "{name}" belongs to domain "{domain_name}"')
def step_device_belongs_to_domain(
    context: runner.Context,
    name: str,
    domain_name: str,
) -> None:
    """Assert the device is assigned to the expected domain."""
    device = DeviceModel.objects.select_related("domain").get(common_name=name)
    assert device.domain is not None, f'Device "{name}" has no domain assigned.'
    assert device.domain.unique_name == domain_name, (
        f'Expected domain "{domain_name}" for device "{name}", '
        f'got "{device.domain.unique_name}".'
    )


@then('the device "{name}" has no domain assigned')
def step_device_has_no_domain(context: runner.Context, name: str) -> None:
    """Assert the device is not assigned to a domain."""
    device = DeviceModel.objects.get(common_name=name)
    assert device.domain is None, f'Device "{name}" unexpectedly belongs to domain "{device.domain}".'


@then('the device "{name}" has an empty serial number')
def step_device_has_empty_serial(context: runner.Context, name: str) -> None:
    """Assert the optional serial number is empty."""
    device = DeviceModel.objects.get(common_name=name)
    assert device.serial_number == "", (
        f'Expected an empty serial number for device "{name}", got "{device.serial_number}".'
    )


@then('the device "{name}" uses no-onboarding')
def step_device_uses_no_onboarding(context: runner.Context, name: str) -> None:
    """Assert the device uses exactly the no-onboarding configuration."""
    device = DeviceModel.objects.select_related(
        "onboarding_config",
        "no_onboarding_config",
    ).get(common_name=name)
    assert device.no_onboarding_config is not None, f'Device "{name}" has no no-onboarding configuration.'
    assert device.onboarding_config is None, f'Device "{name}" unexpectedly has an onboarding configuration.'


@then('the device "{name}" has PKI protocol "{protocol_name}" enabled')
def step_device_protocol_enabled(
    context: runner.Context,
    name: str,
    protocol_name: str,
) -> None:
    """Assert a no-onboarding PKI protocol is enabled for the device."""
    protocol = _protocol_from_name(protocol_name)
    device = DeviceModel.objects.select_related("no_onboarding_config").get(common_name=name)
    config = device.no_onboarding_config
    assert config is not None, f'Device "{name}" has no no-onboarding configuration.'
    assert config.has_pki_protocol(protocol), (
        f'PKI protocol "{protocol_name}" is not enabled for device "{name}". '
        f'Configured protocols: {[item.name for item in config.get_pki_protocols()]}.'
    )


@then('a CMP shared secret was generated for device "{name}"')
def step_cmp_secret_generated(context: runner.Context, name: str) -> None:
    """Assert the creation form generated a CMP shared secret."""
    device = DeviceModel.objects.select_related("no_onboarding_config").get(common_name=name)
    config = device.no_onboarding_config
    assert config is not None, f'Device "{name}" has no no-onboarding configuration.'
    assert config.cmp_shared_secret, f'No CMP shared secret was generated for device "{name}".'


@then('an EST or REST password was generated for device "{name}"')
def step_est_or_rest_password_generated(context: runner.Context, name: str) -> None:
    """Assert the creation form generated the shared EST/REST password."""
    device = DeviceModel.objects.select_related("no_onboarding_config").get(common_name=name)
    config = device.no_onboarding_config
    assert config is not None, f'Device "{name}" has no no-onboarding configuration.'
    assert config.est_password, f'No EST/REST password was generated for device "{name}".'


@given('a device named "{name}" exists in domain "{domain_name}"')
def step_existing_device(context: runner.Context, name: str, domain_name: str) -> None:
    """Create a valid generic device fixture for setup steps."""
    domain, _ = DomainModel.objects.get_or_create(
        unique_name=domain_name,
        defaults={"is_active": True},
    )
    if not domain.is_active:
        domain.is_active = True
        domain.save(update_fields=["is_active"])

    existing = DeviceModel.objects.filter(common_name=name).first()
    if existing is not None:
        context.device = existing
        return

    context.device = create_no_onboarding_device(
        common_name=name,
        serial_number=f"SN-{name}",
        domain=domain,
        protocols=[NoOnboardingPkiProtocol.MANUAL],
    )


@then('exactly one device named "{name}" exists')
def step_exactly_one_device_exists(context: runner.Context, name: str) -> None:
    """Assert duplicate creation did not create a second device."""
    count = DeviceModel.objects.filter(common_name=name).count()
    assert count == 1, f'Expected exactly one device named "{name}", found {count}.'


@then('the device creation form reports that the device name already exists')
def step_duplicate_device_form_error(context: runner.Context) -> None:
    """Assert the duplicate-name validation error is rendered."""
    expected = "Device with this common name already exists."
    content = context.response.content.decode("utf-8")
    assert expected in content, (
        f'Expected duplicate device validation message "{expected}" in response.'
    )


@then('the device "{name}" has an RFC 4122 version 4 UUID')
def step_device_has_uuid4(context: runner.Context, name: str) -> None:
    """Assert the persistent device UUID is a canonical RFC 4122 UUIDv4."""
    device = DeviceModel.objects.get(common_name=name)
    value = device.rfc_4122_uuid
    assert isinstance(value, uuid.UUID), f'Device "{name}" UUID is not a UUID object: {value!r}.'
    assert value.version == 4, f'Device "{name}" UUID is version {value.version}, expected version 4.'
    assert value.variant == uuid.RFC_4122, f'Device "{name}" UUID does not use the RFC 4122 variant.'
    assert device.rfc_4122_uuid_str == str(value), "Device UUID string representation is not canonical."
    assert device.rfc_4122_uuid_str == device.rfc_4122_uuid_str.lower(), "Device UUID must be lowercase."


@then('the devices "{first_name}" and "{second_name}" have different UUIDs')
def step_devices_have_different_uuids(
    context: runner.Context,
    first_name: str,
    second_name: str,
) -> None:
    """Assert independently created devices receive different UUIDs."""
    first = DeviceModel.objects.get(common_name=first_name)
    second = DeviceModel.objects.get(common_name=second_name)
    assert first.rfc_4122_uuid != second.rfc_4122_uuid, (
        f'Devices "{first_name}" and "{second_name}" unexpectedly share UUID '
        f'"{first.rfc_4122_uuid}".'
    )


@when('the admin opens the device list')
def step_open_devices(context: runner.Context) -> None:
    """Open the public device list view."""
    context.response = context.authenticated_client.get("/devices/")


@then('the device list contains "{name}"')
def step_device_list_contains(context: runner.Context, name: str) -> None:
    """Assert the device list renders the device name."""
    content = context.response.content.decode("utf-8")
    assert name in content, f'Device "{name}" was not rendered in the device list.'


@when('the admin deletes that device')
def step_delete_device(context: runner.Context) -> None:
    """Delete the current device through the bulk-delete view."""
    device = context.device
    context.response = context.authenticated_client.post(
        f"/devices/delete-device/{device.pk}/",
        {"pks": str(device.pk)},
        follow=True,
    )


@then('the device "{name}" no longer exists')
def step_device_deleted(context: runner.Context, name: str) -> None:
    """Assert the device was deleted."""
    assert not DeviceModel.objects.filter(common_name=name).exists(), (
        f'Device "{name}" still exists after deletion.'
    )


@when('the admin opens non-existent device id {device_id:d}')
def step_missing_device(context: runner.Context, device_id: int) -> None:
    """Request a current device-specific view for a non-existent primary key."""
    context.response = context.authenticated_client.get(
        f"/devices/certificate-lifecycle-management/{device_id}/"
    )


@when('the admin opens the onboarding device creation page')
def step_open_onboarding_create(context: runner.Context) -> None:
    """Open the onboarding-device creation page retained for onboarding.feature."""
    context.response = context.authenticated_client.get("/devices/create/onboarding/")


@then('the onboarding form contains a protocol selector')
def step_onboarding_protocol_selector(context: runner.Context) -> None:
    """Assert the onboarding form exposes protocol selection."""
    content = context.response.content.decode("utf-8")
    assert "onboarding_protocol" in content
