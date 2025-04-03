"""Python steps file for R_101."""

from behave import given, runner, then, when


@given('the TrustPoint component {component} is selected')
def step_given_component_selected(context: runner.Context, component: str) -> None:  # noqa: ARG001
    """Simulates selecting a TrustPoint component in the security configuration panel.

    Args:
        context (runner.Context): Behave context.
        component (str): The selected TrustPoint component.
    """
    msg = f'STEP: Given the TrustPoint component {component} is selected'
    raise AssertionError(msg)


@given('the TrustPoint component {component} has security level {security_level}')
def step_given_component_has_security_level(context: runner.Context, component: str, security_level: str) -> None:  # noqa: ARG001
    """Ensures that the TrustPoint component has a specified security level.

    Args:
        context (runner.Context): Behave context.
        component (str): The TrustPoint component.
        security_level (str): The current security level.
    """
    msg = f'STEP: Given the TrustPoint component {component} has security level {security_level}'
    raise AssertionError(msg)


@when('the admin sets the security level to {security_level}')
def step_when_admin_sets_security_level(context: runner.Context, security_level: str) -> None:  # noqa: ARG001
    """Simulates an admin setting a security level for a component.

    Args:
        context (runner.Context): Behave context.
        security_level (str): The new security level to be set.
    """
    msg = f'STEP: When the admin sets the security level to {security_level}'
    raise AssertionError(msg)


@when('the system is restarted')
def step_when_system_restarts(context: runner.Context) -> None:  # noqa: ARG001
    """Simulates restarting the system.

    Args:
        context (runner.Context): Behave context.
    """
    msg = 'STEP: When the system is restarted'
    raise AssertionError(msg)


@when('an unauthorized user attempts access')
def step_when_unauthorized_access_attempted(context: runner.Context) -> None:  # noqa: ARG001
    """Simulates an unauthorized user attempting to access a system component.

    Args:
        context (runner.Context): Behave context.
    """
    msg = 'STEP: When an unauthorized user attempts access'
    raise AssertionError(msg)


@then('the system should apply the security level {security_level}')
def step_then_system_applies_security_level(context: runner.Context, security_level: str) -> None:  # noqa: ARG001
    """Ensures that the system applies the specified security level.

    Args:
        context (runner.Context): Behave context.
        security_level (str): The expected security level applied.
    """
    msg = f'STEP: Then the system should apply the security level {security_level}'
    raise AssertionError(msg)


@then('the system should reject the input with error {error_message}')
def step_then_reject_invalid_input(context: runner.Context, error_message: str) -> None:  # noqa: ARG001
    """Ensures that an invalid security level input is rejected with an error.

    Args:
        context (runner.Context): Behave context.
        error_message (str): The expected error message.
    """
    msg = f'STEP: Then the system should reject the input with error {error_message}'
    raise AssertionError(msg)


@then('the TrustPoint component {component} should still have security level {security_level}')
def step_then_security_level_persists(context: runner.Context, component: str, security_level: str) -> None:  # noqa: ARG001
    """Ensures that the security level persists after a system restart.

    Args:
        context (runner.Context): Behave context.
        component (str): The TrustPoint component.
        security_level (str): The expected security level after restart.
    """
    msg = f'STEP: Then the TrustPoint component {component} should still have security level {security_level}'
    raise AssertionError(msg)


@then('access should be denied')
def step_then_access_denied(context: runner.Context) -> None:  # noqa: ARG001
    """Ensures that access is denied based on security level settings.

    Args:
        context (runner.Context): Behave context.
    """
    msg = 'STEP: Then access should be denied'
    raise AssertionError(msg)


@then('the system should log the security level change with details')
def step_then_log_security_change(context: runner.Context) -> None:  # noqa: ARG001
    """Ensures that changes to security levels are logged.

    Args:
        context (runner.Context): Behave context.
    """
    msg = 'STEP: Then the system should log the security level change with details'
    raise AssertionError(msg)
