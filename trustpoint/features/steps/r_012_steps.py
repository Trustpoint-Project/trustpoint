"""Python steps file for R_012."""

from behave import given, runner, then, when


@given('the system supports the following languages:')
def step_given_supported_languages(context: runner.Context) -> None:  # noqa: ARG001
    """Ensures that the system supports multiple languages.

    Args:
        context (runner.Context): Behave context.
    """
    msg = 'STEP: Given the system supports the following languages'
    raise AssertionError(msg)


@given('a new user accesses the system with browser language {language}')
def step_given_new_user_with_browser_language(context: runner.Context, language: str) -> None:  # noqa: ARG001
    """Simulates a new user accessing the system with a specified browser language.

    Args:
        context (runner.Context): Behave context.
        language (str): The language detected from the user's browser settings.
    """
    msg = f'STEP: Given a new user accesses the system with browser language {language}'
    raise AssertionError(msg)


@then('the system should display the UI in {language}')
def step_then_ui_displays_language(context: runner.Context, language: str) -> None:  # noqa: ARG001
    """Ensures that the UI is displayed in the correct language.

    Args:
        context (runner.Context): Behave context.
        language (str): Expected language for the UI.
    """
    msg = f'STEP: Then the system should display the UI in {language}'
    raise AssertionError(msg)


@given('a logged-in user')
def step_given_logged_in_user(context: runner.Context) -> None:  # noqa: ARG001
    """Simulates a logged-in user.

    Args:
        context (runner.Context): Behave context.
    """
    msg = 'STEP: Given a logged-in user'
    raise AssertionError(msg)


@when('the user selects {language} from the language settings')
def step_when_user_selects_language(context: runner.Context, language: str) -> None:  # noqa: ARG001
    """Simulates a user selecting a different language.

    Args:
        context (runner.Context): Behave context.
        language (str): Language chosen by the user.
    """
    msg = f'STEP: When the user selects {language} from the language settings'
    raise AssertionError(msg)


@given('a user has selected {language} as their preferred language')
def step_given_user_preferred_language(context: runner.Context, language: str) -> None:  # noqa: ARG001
    """Simulates a user with a saved language preference.

    Args:
        context (runner.Context): Behave context.
        language (str): The preferred language set by the user.
    """
    msg = f'STEP: Given a user has selected {language} as their preferred language'
    raise AssertionError(msg)


@when('the user logs out and logs back in')
def step_when_user_relogs(context: runner.Context) -> None:  # noqa: ARG001
    """Simulates a user logging out and logging back in.

    Args:
        context (runner.Context): Behave context.
    """
    msg = 'STEP: When the user logs out and logs back in'
    raise AssertionError(msg)
