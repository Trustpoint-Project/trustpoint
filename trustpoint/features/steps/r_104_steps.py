"""Python steps file for R_104."""  # noqa: INP001


from behave import given, runner, then, when


@given('the user has role {role}')
def step_given_user_role(context: runner.Context, role: str) -> None:  # noqa: ARG001
    """Ensures the user has a specified role.

    Args:
        context (runner.Context): Behave context.
        role (str): The role assigned to the user.
    """
    msg = f'STEP: Given the user has role {role}'
    raise AssertionError(msg)


@given('a certificate template named {template_name} exists')
def step_given_certificate_template_exists(context: runner.Context, template_name: str) -> None:  # noqa: ARG001
    """Ensures that a specific certificate template exists.

    Args:
        context (runner.Context): Behave context.
        template_name (str): The name of the certificate template.
    """
    msg = f'STEP: Given a certificate template named {template_name} exists'
    raise AssertionError(msg)


@when('the user attempts to access certificate templates')
def step_when_user_attempts_access_templates(context: runner.Context) -> None:  # noqa: ARG001
    """Simulates a user attempting to access certificate templates.

    Args:
        context (runner.Context): Behave context.
    """
    msg = 'STEP: When the user attempts to access certificate templates'
    raise AssertionError(msg)


@when('the user attempts to modify the certificate template')
def step_when_user_attempts_modify_template(context: runner.Context) -> None:  # noqa: ARG001
    """Simulates a user attempting to modify a certificate template.

    Args:
        context (runner.Context): Behave context.
    """
    msg = 'STEP: When the user attempts to modify the certificate template'
    raise AssertionError(msg)


@when('an unauthorized user attempts to access it')
def step_when_unauthorized_access_attempted(context: runner.Context) -> None:  # noqa: ARG001
    """Simulates an unauthorized user attempting to access a sensitive certificate template.

    Args:
        context (runner.Context): Behave context.
    """
    msg = 'STEP: When an unauthorized user attempts to access it'
    raise AssertionError(msg)


@when('a non-admin user attempts to delete it')
def step_when_non_admin_attempts_delete(context: runner.Context) -> None:  # noqa: ARG001
    """Simulates a non-admin user attempting to delete a certificate template.

    Args:
        context (runner.Context): Behave context.
    """
    msg = 'STEP: When a non-admin user attempts to delete it'
    raise AssertionError(msg)


@when('an admin exports the template')
def step_when_admin_exports_template(context: runner.Context) -> None:  # noqa: ARG001
    """Simulates an admin exporting a certificate template.

    Args:
        context (runner.Context): Behave context.
    """
    msg = 'STEP: When an admin exports the template'
    raise AssertionError(msg)


@when('a non-admin user attempts to export the template')
def step_when_non_admin_attempts_export(context: runner.Context) -> None:  # noqa: ARG001
    """Simulates a non-admin user attempting to export a certificate template.

    Args:
        context (runner.Context): Behave context.
    """
    msg = 'STEP: When a non-admin user attempts to export the template'
    raise AssertionError(msg)


@then('access should be {access_outcome}')
def step_then_access_outcome(context: runner.Context, access_outcome: str) -> None:  # noqa: ARG001
    """Ensures that access to certificate templates is correctly granted or denied.

    Args:
        context (runner.Context): Behave context.
        access_outcome (str): The expected access outcome ('granted' or 'denied').
    """
    msg = f'STEP: Then access should be {access_outcome}'
    raise AssertionError(msg)


@then('modification should be {modification_outcome}')
def step_then_modification_outcome(context: runner.Context, modification_outcome: str) -> None:  # noqa: ARG001
    """Ensures that modification attempts are correctly handled.

    Args:
        context (runner.Context): Behave context.
        modification_outcome (str): The expected modification outcome ('allowed' or 'denied').
    """
    msg = f'STEP: Then modification should be {modification_outcome}'
    raise AssertionError(msg)


@then('the deletion should be rejected')
def step_then_deletion_rejected(context: runner.Context) -> None:  # noqa: ARG001
    """Ensures that unauthorized deletion attempts are rejected.

    Args:
        context (runner.Context): Behave context.
    """
    msg = 'STEP: Then the deletion should be rejected'
    raise AssertionError(msg)


@then('an error message {error_message} should be shown')
def step_then_error_message_shown(context: runner.Context, error_message: str) -> None:  # noqa: ARG001
    """Ensures that an appropriate error message is shown for unauthorized actions.

    Args:
        context (runner.Context): Behave context.
        error_message (str): The expected error message.
    """
    msg = f'STEP: Then an error message {error_message} should be shown'
    raise AssertionError(msg)


@then('the exported template should be encrypted')
def step_then_export_encrypted(context: runner.Context) -> None:  # noqa: ARG001
    """Ensures that exported certificate templates are encrypted.

    Args:
        context (runner.Context): Behave context.
    """
    msg = 'STEP: Then the exported template should be encrypted'
    raise AssertionError(msg)


@then('export should be denied')
def step_then_export_denied(context: runner.Context) -> None:  # noqa: ARG001
    """Ensures that unauthorized export attempts are denied.

    Args:
        context (runner.Context): Behave context.
    """
    msg = 'STEP: Then export should be denied'
    raise AssertionError(msg)


@then('the attempt should be logged')
def step_then_attempt_should_be_logged(context: runner.Context) -> None:  # noqa: ARG001
    """Ensures that unauthorized actions are logged.

    Args:
        context (runner.Context): Behave context.
    """
    msg = 'STEP: Then the attempt should be logged'
    raise AssertionError(msg)
