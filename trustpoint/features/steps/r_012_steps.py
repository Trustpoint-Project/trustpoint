"""Python steps file for R_012."""

from behave import given, runner, then, when
from django.conf import settings
from django.test import Client

TRANSLATION_LOOKUP = {
    'login': {
        'English': 'Username',
        'German': 'Benutzername',
    },
    'dashboard': {
        'English': 'Dashboard',
        'German': 'Übersicht',
    },
}

supported_languages = {name.capitalize(): code for code, name in settings.LANGUAGES}


@given('the system supports the following languages:')
def step_given_supported_languages(context: runner.Context) -> None:  # noqa: ARG001
    """Ensures that the system supports multiple languages.

    Args:
        context (runner.Context): Behave context.
    """

    expected_languages = [row['language'] for row in context.table]
    print(f'Expected languages: {expected_languages}')
    available_languages = list(supported_languages.keys())
    print(f'Available languages: {available_languages}')
    for lang in expected_languages:
        assert lang in available_languages, f"Language '{lang}' is not supported by the system"


@given('a new user accesses the system with browser language {language}')
def step_given_new_user_with_browser_language(context: runner.Context, language: str) -> None:  # noqa: ARG001
    """Simulates a new user accessing the system with a specified browser language.

    Args:
        context (runner.Context): Behave context.
        language (str): The language detected from the user's browser settings.
    """
    context.client = Client()
    lang_code = supported_languages.get(language)
    context.client.cookies.load({'django_language': lang_code})

    # Send GET request to home page
    context.response = context.client.get('/users/login/')
    assert context.response.status_code == 200, f'Login page access failed: got {context.response.status_code} instead.'
    context.page = 'login'


@then('the system should display the UI in {language}')
def step_then_ui_displays_language(context: runner.Context, language: str) -> None:  # noqa: ARG001
    """Ensures that the UI is displayed in the correct language.

    Args:
        context (runner.Context): Behave context.
        language (str): Expected language for the UI.
    """

    expected_text = TRANSLATION_LOOKUP.get(context.page, {}).get(language)
    if hasattr(context, 'response') and context.response is not None:
        content = context.response.content.decode('utf-8')
    assert expected_text in content, f"Expected '{expected_text}' not found in page content"


@when('the user selects {language} from the language settings')
def step_when_user_selects_language(context: runner.Context, language: str) -> None:  # noqa: ARG001
    """Simulates a user selecting a different language.

    Args:
        context (runner.Context): Behave context.
        language (str): Language chosen by the user.
    """
    # Navigate to the language settings page
    context.response = context.authenticated_client.get('/management/settings')
    lang_code = supported_languages.get(language)
    context.response = context.authenticated_client.post(
        '/i18n/setlang/',
        {
            'language': lang_code,
            'next': '/',
        },
        follow=True,
    )

    assert lang_code in context.response.content.decode()
    cookies = context.authenticated_client.cookies
    assert 'django_language' in cookies, 'Language cookie not set'
    language_cookie = cookies['django_language']

    assert language_cookie.value == lang_code, f"Expected cookie value '{lang_code}', got '{language_cookie['value']}'"

    context.page = 'dashboard'


@when('the user logs out and logs back in')
def step_when_user_relogin(context: runner.Context) -> None:  # noqa: ARG001
    """Simulates a user logging out and logging back in.

    Args:
        context (runner.Context): Behave context.
    """
    context.authenticated_client.logout()
    client = Client()
    login_success = client.login(username='admin', password='testing321')  # noqa: S106
    if not login_success:
        msg = 'Login unsuccessful'
        raise AssertionError(msg)  # noqa: TRY301

    context.authenticated_client = client
