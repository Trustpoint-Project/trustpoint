"""Python steps file for R_101."""  # noqa: INP001

from enum import Enum

from behave import given, runner, then, when

Validity = Enum('valid', 'expired', 'revoked', 'self-signed', 'tampered')
Allow_Deny = Enum('allow', 'deny')


@given('the system enforces certificate validation for all devices')
def step_given_system_enforces_cert_validation(context: runner.Context) -> None:  # noqa: ARG001
    """Ensures that the system requires all devices to present valid certificates for communication.

    Args:
        context (runner.Context): Behave context.
    """
    msg = 'STEP: Given the system enforces certificate validation for all devices'
    raise AssertionError(msg)


@given('a device has a {validity} certificate')
def step_given_device_with_cert(context: runner.Context, validity: Validity) -> None:  # noqa: ARG001
    """Simulates a device possessing a certificate.

    Args:
        context (runner.Context): Behave context.
        validity (Validity): The validity.
    """
    msg = f'STEP: Given a device has a {validity} certificate'
    raise AssertionError(msg)


@given('a device does not present a certificate')
def step_given_device_without_cert(context: runner.Context) -> None:  # noqa: ARG001
    """Simulates a device attempting to communicate without providing a certificate.

    Args:
        context (runner.Context): Behave context.
    """
    msg = 'STEP: Given a device does not present a certificate'
    raise AssertionError(msg)


@when('the device attempts to establish communication')
def step_when_device_attempts_communication(context: runner.Context) -> None:  # noqa: ARG001
    """Simulates a device attempting to establish communication with the system.

    Args:
        context (runner.Context): Behave context.
    """
    msg = 'STEP: When the device attempts to establish communication'
    raise AssertionError(msg)


@then('the system should {allow_deny} the communication')
def step_then_allow_deny_communication(context: runner.Context, allow_deny: Allow_Deny) -> None:  # noqa: ARG001
    """Ensures that the system allows/denies communication when a valid certificate is presented.

    Args:
        context (runner.Context): Behave context.
        allow_deny (Allow_Deny): allow or deny.
    """
    msg = f'STEP: Then the system should {allow_deny} the communication'
    raise AssertionError(msg)


@then('log the authentication failure with reason {reason}')
def step_then_log_failure(context: runner.Context, reason: str) -> None:  # noqa: ARG001
    """Ensures that the system logs authentication failures with the appropriate reason.

    Args:
        context (runner.Context): Behave context.
        reason (str): The reason for authentication failure.
    """
    msg = f'STEP: Then log the authentication failure with reason {reason}'
    raise AssertionError(msg)
