"""Python steps file for R_012."""

from behave import given, runner, then, when
from django.conf import settings
from django.test import Client
from django.contrib.auth.models import User
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import Select
import time

TRANSLATION_LOOKUP = {
    "login": {
        "English": "Username",
        "German": "Benutzername",
    },
    "dashboard": {
        "English": "Dashboard",
        "German": "Übersicht",
    }
}

supported_languages = {
    name.capitalize(): code for code, name in settings.LANGUAGES
}

@given('the system supports the following languages:')
def step_given_supported_languages(context: runner.Context) -> None:  # noqa: ARG001
    """Ensures that the system supports multiple languages.

    Args:
        context (runner.Context): Behave context.
    """

    expected_languages = [
        row['language'] for row in context.table
    ]
    print(f"Expected languages: {expected_languages}")
    available_languages = list(supported_languages.keys())
    print(f"Available languages: {available_languages}")
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
    context.response = context.client.get("/users/login/")
    assert context.response.status_code == 200, f"Login page access failed: got {context.response.status_code} instead."
    context.page = 'login'


@then('the system should display the UI in {language}')
def step_then_ui_displays_language(context: runner.Context, language: str) -> None:  # noqa: ARG001
    """Ensures that the UI is displayed in the correct language.

    Args:
        context (runner.Context): Behave context.
        language (str): Expected language for the UI.
    """

    expected_text = TRANSLATION_LOOKUP.get(context.page, {}).get(language)
    content = context.browser.page_source
    if hasattr(context, "response") and context.response is not None:
        content = context.response.content.decode("utf-8")
    assert expected_text in content, f"Expected '{expected_text}' not found in page content"

@given('a logged-in user')
def step_given_logged_in_user(context: runner.Context) -> None:  # noqa: ARG001
    """Simulates a logged-in user.

    Args:
        context (runner.Context): Behave context.
    """
    # Create NTEU user if doesn't exist
    username = "admin"
    password = "testing321"
    if not User.objects.filter(username=username).exists():
        User.objects.create_user(username=username, password=password)

    # Log in through the browser
    context.browser.get(context.base_url + '/users/login/')

    context.browser.find_element(By.NAME, "username").send_keys(username)
    context.browser.find_element(By.NAME, "password").send_keys(password)
    context.browser.find_element(By.XPATH, "//button[contains(text(), 'Login')]").click()

    time.sleep(1)  # Allow redirect to complete
    assert "Dashboard" in context.browser.page_source or "Übersicht" in context.browser.page_source, "Login failed"


@when('the user selects {language} from the language settings')
def step_when_user_selects_language(context: runner.Context, language: str) -> None:  # noqa: ARG001
    """Simulates a user selecting a different language.

    Args:
        context (runner.Context): Behave context.
        language (str): Language chosen by the user.
    """
    # Navigate to the language settings page
    context.browser.get(context.base_url + '/settings/language/')
    select_element = Select(context.browser.find_element(By.NAME, "language"))

    lang_code = supported_languages.get(language)
    # Select by value (e.g., "en", "de")
    select_element.select_by_value(lang_code)

    # Submit the form if needed (depends on your form setup)
    # If there's a submit button:
    submit_btn = context.browser.find_element(By.CSS_SELECTOR, 'button[form="language_configuration"]')

    submit_btn.click()

    # Wait briefly for the page to reflect language change
    time.sleep(1)
    
    language_cookie = context.browser.get_cookie('django_language')
    assert language_cookie, "Language cookie not set"
    assert language_cookie['value'] == lang_code, f"Expected cookie value '{lang_code}', got '{language_cookie['value']}'"

    # Log in through the browser
    context.browser.get(context.base_url + '/home/dashboard/')
    time.sleep(1)
    context.page = 'dashboard'

@when('the user logs out and logs back in')
def step_when_user_relogs(context: runner.Context) -> None:  # noqa: ARG001
    """Simulates a user logging out and logging back in.

    Args:
        context (runner.Context): Behave context.
    """
    # Resize the browser window to a larger size to make sure the menu is expanded
    context.browser.set_window_size(1200, 800)
    logout_btn = context.browser.find_element(By.CSS_SELECTOR, "button.tp-menu-head")
    logout_btn.click()
    login_user(context)

def login_user(context, username="admin", password="testing321"):
    # Create user if not exists
    if not User.objects.filter(username=username).exists():
        User.objects.create_user(username=username, password=password)

    # Navigate to login page
    context.browser.get(context.base_url + '/users/login/')

    # Fill and submit the login form
    context.browser.find_element(By.NAME, "username").send_keys(username)
    context.browser.find_element(By.NAME, "password").send_keys(password)
    context.browser.find_element(By.XPATH, "//button[contains(text(), 'Login')]").click()
    time.sleep(1)

