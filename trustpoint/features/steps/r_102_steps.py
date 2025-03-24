"""Python steps file for R_102."""

from behave import given, runner, then, when


@given('the system enforces encrypted communication with algorithm {algorithm}')
def step_given_enforced_encryption(context: runner.Context, algorithm: str) -> None:  # noqa: ARG001
    """Ensures that the system enforces encrypted communication using the specified algorithm.

    Args:
        context (runner.Context): Behave context.
        algorithm (str): The encryption algorithm enforced by the system.
    """
    msg = f'STEP: Given the system enforces encrypted communication with algorithm {algorithm}'
    raise AssertionError(msg)


@given('a machine attempts to communicate using {algorithm}')
def step_given_machine_attempts_encryption(context: runner.Context, algorithm: str) -> None:  # noqa: ARG001
    """Simulates a machine attempting to communicate using a specific encryption algorithm.

    Args:
        context (runner.Context): Behave context.
        algorithm (str): The encryption algorithm the machine attempts to use.
    """
    msg = f'STEP: Given a machine attempts to communicate using {algorithm}'
    raise AssertionError(msg)


@given('a machine attempts to communicate without encryption')
def step_given_machine_attempts_without_encryption(context: runner.Context) -> None:  # noqa: ARG001
    """Simulates a machine attempting to communicate without using encryption.

    Args:
        context (runner.Context): Behave context.
    """
    msg = 'STEP: Given a machine attempts to communicate without encryption'
    raise AssertionError(msg)


@given('two machines establish a secure session using {key_exchange}')
def step_given_secure_key_exchange(context: runner.Context, key_exchange: str) -> None:  # noqa: ARG001
    """Simulates two machines establishing a secure session using a specified key exchange mechanism.

    Args:
        context (runner.Context): Behave context.
        key_exchange (str): The key exchange protocol being used.
    """
    msg = f'STEP: Given two machines establish a secure session using {key_exchange}'
    raise AssertionError(msg)


@given('an encrypted message is tampered with')
def step_given_encrypted_message_tampered(context: runner.Context) -> None:  # noqa: ARG001
    """Simulates an encrypted message being tampered with by a third party.

    Args:
        context (runner.Context): Behave context.
    """
    msg = 'STEP: Given an encrypted message is tampered with'
    raise AssertionError(msg)


@when('the system verifies the encryption')
def step_when_system_verifies_encryption(context: runner.Context) -> None:  # noqa: ARG001
    """Simulates the system verifying the encryption mechanism of the communication.

    Args:
        context (runner.Context): Behave context.
    """
    msg = 'STEP: When the system verifies the encryption'
    raise AssertionError(msg)


@when('the system verifies the key exchange')
def step_when_system_verifies_key_exchange(context: runner.Context) -> None:  # noqa: ARG001
    """Simulates the system verifying that the key exchange mechanism used is correct.

    Args:
        context (runner.Context): Behave context.
    """
    msg = 'STEP: When the system verifies the key exchange'
    raise AssertionError(msg)


@when('the system detects tampering')
def step_when_system_detects_tampering(context: runner.Context) -> None:  # noqa: ARG001
    """Simulates the system detecting tampering with an encrypted message.

    Args:
        context (runner.Context): Behave context.
    """
    msg = 'STEP: When the system detects tampering'
    raise AssertionError(msg)


@then('the communication should be {continuing_action}')
def step_then_allow_communication(context: runner.Context, continuing_action: str) -> None:  # noqa: ARG001
    """Ensures that communication is allowed/denied/terminated when encryption meets the system's requirements.

    Args:
        context (runner.Context): Behave context.
        continuing_action (str): The continuing action.
    """
    msg = f'STEP: Then the communication should be {continuing_action}'
    raise AssertionError(msg)


@then('log the failure with reason {reason}')
def step_then_log_failure(context: runner.Context, reason: str) -> None:  # noqa: ARG001
    """Ensures that the system logs authentication failures with the appropriate reason.

    Args:
        reason (str): The reason for encryption failure.

    Args:
        context (runner.Context): Behave context.
    """
    msg = f'STEP: Then log the failure with reason {reason}'
    raise AssertionError(msg)
