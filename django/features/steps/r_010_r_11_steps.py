"""Python steps file for R_010 and R_011."""  # noqa: INP001

from enum import Enum

from behave import given, runner, then, when

OnboardingProtocol = Enum('CMP', 'EST')


@given('the {endpoint} endpoint is available')
def step_given_endpoint_available(context: runner.Context, endpoint: str) -> None:  # noqa: ARG001
    """Ensures that the endpoint is accessible before testing.

    Args:
        context (runner.Context): Behave context.
        endpoint (str): The endpoint.
    """
    msg = 'STEP: Given the endpoint is available'
    raise AssertionError(msg)


@given('a new device with identifier {device_id}')
def step_given_new_device(context: runner.Context, device_id: str) -> None:  # noqa: ARG001
    """Simulates a new device before sending a CMP request.

    Args:
        context (runner.Context): Behave context.
        device_id (str): Unique identifier for the new device.
    """
    msg = f'STEP: Given a new device with identifier {device_id}'
    raise AssertionError(msg)


@when('the device sends a {onboarding_protocol} request for a new certificate')
def step_when_device_requests_certificate(context: runner.Context, onboarding_protocol: OnboardingProtocol) -> None:  # noqa: ARG001
    """Simulates a new device requesting a certificate via the CMP endpoint.

    Args:
        context (runner.Context): Behave context.
        onboarding_protocol (OnboardingProtocol): The onboarding protocol.
    """
    msg = f'STEP: When the device sends a {onboarding_protocol} request for a new certificate'
    raise AssertionError(msg)


@then('the system should issue a new certificate for {device_id}')
def step_then_system_issues_certificate(context: runner.Context, device_id: str) -> None:  # noqa: ARG001
    """Ensures that the system issues a certificate for a requesting device.

    Args:
        context (runner.Context): Behave context.
        device_id (str): Unique identifier for the device.
    """
    msg = f'STEP: Then the system should issue a certificate for {device_id}'
    raise AssertionError(msg)


@then('the device should store the issued certificate')
def step_then_device_stores_certificate(context: runner.Context) -> None:  # noqa: ARG001
    """Ensures that the device successfully stores its issued certificate.

    Args:
        context (runner.Context): Behave context.
    """
    msg = 'STEP: Then the device should store the issued certificate'
    raise AssertionError(msg)


@given('an onboarded device with identifier {device_id} and an active certificate')
def step_given_onboarded_device(context: runner.Context, device_id: str) -> None:  # noqa: ARG001
    """Ensures that a device is onboarded and has an active certificate.

    Args:
        context (runner.Context): Behave context.
        device_id (str): Unique identifier for the onboarded device.
    """
    msg = f'STEP: Given an onboarded device with identifier {device_id} and an active certificate'
    raise AssertionError(msg)


@when('the device sends a {onboarding_protocol} request for certificate renewal')
def step_when_device_renews_certificate(context: runner.Context, onboarding_protocol: OnboardingProtocol) -> None:  # noqa: ARG001
    """Simulates a device requesting a certificate renewal.

    Args:
        context (runner.Context): Behave context.
        onboarding_protocol (OnboardingProtocol): The onboarding protocol.
    """
    msg = f'STEP: When the device sends a {onboarding_protocol} request for certificate renewal'
    raise AssertionError(msg)


@then('the device should replace its old certificate with the new one')
def step_then_device_replaces_certificate(context: runner.Context) -> None:  # noqa: ARG001
    """Ensures that the device updates its certificate upon renewal.

    Args:
        context (runner.Context): Behave context.
    """
    msg = 'STEP: Then the device should replace its old certificate with the new one'
    raise AssertionError(msg)


@given('a device with invalid credentials')
def step_given_invalid_device(context: runner.Context) -> None:  # noqa: ARG001
    """Simulates a device with incorrect authentication details.

    Args:
        context (runner.Context): Behave context.
    """
    msg = 'STEP: Given a device with invalid credentials'
    raise AssertionError(msg)


@when('the device sends a {onboarding_protocol} request')
def step_when_invalid_device_requests(context: runner.Context, onboarding_protocol: OnboardingProtocol) -> None:  # noqa: ARG001
    """Simulates an unauthorized device attempting to access the CMP endpoint.

    Args:
        context (runner.Context): Behave context.
        onboarding_protocol (OnboardingProtocol): The onboarding protocol.
    """
    msg = f'STEP: When the device sends a {onboarding_protocol} request'
    raise AssertionError(msg)


@then('the system should reject the request with an "Unauthorized" error')
def step_then_reject_unauthorized_request(context: runner.Context) -> None:  # noqa: ARG001
    """Ensures that the system rejects the request.

    Args:
        context (runner.Context): Behave context.
    """
    msg = 'STEP: Then the system should reject the request with an "Unauthorized" error'
    raise AssertionError(msg)


@given('a registered device with identifier {device_id} and a valid certificate')
def step_given_registered_device(context: runner.Context, device_id: str) -> None:  # noqa: ARG001
    """Ensures that a device is registered and has a valid certificate.

    Args:
        context (runner.Context): Behave context.
        device_id (str): Unique identifier for the device.
    """
    msg = f'STEP: Given a registered device with identifier {device_id} and a valid certificate'
    raise AssertionError(msg)


@when('an admin revokes the certificate for {device_id}')
def step_when_admin_revokes_certificate(context: runner.Context, device_id: str) -> None:  # noqa: ARG001
    """Simulates an admin revoking a device's certificate.

    Args:
        context (runner.Context): Behave context.
        device_id (str): Unique identifier for the device.
    """
    msg = f'STEP: When an admin revokes the certificate for {device_id}'
    raise AssertionError(msg)


@then('the system should update the revocation list')
def step_then_revocation_list_updated(context: runner.Context) -> None:  # noqa: ARG001
    """Ensures that the system updates its revocation list upon certificate revocation.

    Args:
        context (runner.Context): Behave context.
    """
    msg = 'STEP: Then the system should update the revocation list'
    raise AssertionError(msg)


@then('{device_id} should no longer authenticate using its certificate')
def step_then_device_should_no_longer_auth_using_cert(context: runner.Context) -> None:  # noqa: ARG001
    """Ensures that the device should no longer authenticate using its certificate.

    Args:
        context (runner.Context): Behave context.
    """
    msg = 'STEP: Then {device_id} should no longer authenticate using its certificate'
    raise AssertionError(msg)


@given('{num_devices} devices are requesting certificates simultaneously via {onboarding_protocol}')
def step_given_devices_requesting_certs(
    context: runner.Context,  # noqa: ARG001
    num_devices: int,
    onboarding_protocol: OnboardingProtocol,
) -> None:
    """A number of device are requesting certificates simultaneously.

    Args:
        context (runner.Context): Behave context.
        num_devices (int): The number of devices.
        onboarding_protocol (OnboardingProtocol): The onboarding protocol.
    """
    msg = f'STEP: Given {num_devices} devices are requesting certificates simultaneously via {onboarding_protocol}'
    raise AssertionError(msg)


@when('the {onboarding_protocol} endpoint processes the requests')
def step_when_the_protocol_endpoint_processes_the_req(
    context: runner.Context,  # noqa: ARG001
    onboarding_protocol: OnboardingProtocol,
) -> None:
    """The protocol processes the request.

    Args:
        context (runner.Context): Behave context.
        onboarding_protocol (OnboardingProtocol): The onboarding protocol.
    """
    msg = f'STEP: When the {onboarding_protocol} endpoint processes the requests'
    raise AssertionError(msg)


@then('all certificates should be issued within {max_response_time} milliseconds')
def step_then_all_certs_should_be_issued_within_time(context: runner.Context, max_response_time: int) -> None:  # noqa: ARG001
    """All certificates should be issued within a given time.

    Args:
        context (runner.Context): Behave context.
        max_response_time (int): The number of devices.
    """
    msg = f'STEP: Then all certificates should be issued within {max_response_time} milliseconds'
    raise AssertionError(msg)
