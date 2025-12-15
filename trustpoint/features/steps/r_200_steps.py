"""Python steps file for R_200 - Docker Setup Wizard test."""

from __future__ import annotations

import re
import time

import requests
from behave import given, runner, then, when

HTTP_OK = 200
HTTP_REDIRECT = 302
DOCKER_URL = 'http://localhost'


def extract_csrf_token(html_content: str) -> str:
    """Extract CSRF token from HTML content.

    Args:
        html_content: The HTML content containing the CSRF token

    Returns:
        The CSRF token value

    Raises:
        AssertionError: If no CSRF token is found
    """
    match = re.search(r'csrfmiddlewaretoken["\']?\s*value=["\']([^"\']+)["\']', html_content)
    if not match:
        msg = 'CSRF token not found in response'
        raise AssertionError(msg)
    return match.group(1)


@given('a fresh Trustpoint Docker container is running')
def step_docker_container_running(context: runner.Context) -> None:
    """Ensures a fresh Trustpoint Docker container is running.

    This step assumes Docker Compose has been used to start the services.
    It verifies that the container is accessible.

    Args:
        context: The behave context
    """
    # Create a session to maintain cookies across requests
    context.session = requests.Session()
    context.base_url = DOCKER_URL

    # Verify the application is accessible
    max_retries = 30
    for attempt in range(max_retries):
        try:
            response = context.session.get(context.base_url, timeout=5)
            if response.status_code in [HTTP_OK, HTTP_REDIRECT]:
                break
        except Exception:  # noqa: BLE001
            if attempt < max_retries - 1:
                time.sleep(2)
            else:
                msg = 'Docker container not accessible after maximum retries'
                raise AssertionError(msg) from None


@when('the user accesses the setup wizard')
def step_access_setup_wizard(context: runner.Context) -> None:
    """Accesses the setup wizard landing page.

    Args:
        context: The behave context
    """
    context.response = context.session.get(f'{context.base_url}/', allow_redirects=True)
    assert context.response.status_code == HTTP_OK, \
        f'Failed to access setup wizard: {context.response.status_code}'


@then('the wizard should be at the crypto storage setup step')
def step_verify_crypto_storage_step(context: runner.Context) -> None:
    """Verifies the wizard is at the crypto storage selection step.

    Args:
        context: The behave context
    """
    content_lower = context.response.text.lower()
    assert 'crypto' in content_lower or \
           'storage' in content_lower, \
           'Not at crypto storage setup step'


@when('the user selects "{storage_type}" as crypto storage')
def step_select_crypto_storage(context: runner.Context, storage_type: str) -> None:
    """Selects the crypto storage type.

    Args:
        context: The behave context
        storage_type: The type of crypto storage to select
    """
    csrf_token = extract_csrf_token(context.response.text)

    # File system storage is typically option 0 or 1
    storage_option = '0' if 'file' in storage_type.lower() else '1'

    context.crypto_form_data = {
        'csrfmiddlewaretoken': csrf_token,
        'crypto_storage_type': storage_option,
    }


@when('the user proceeds to the next step')
def step_proceed_next(context: runner.Context) -> None:
    """Proceeds to the next step in the wizard.

    Args:
        context: The behave context
    """
    # Get current URL for posting
    current_url = context.response.url

    # Submit the current form data if available
    if hasattr(context, 'crypto_form_data'):
        context.response = context.session.post(
            current_url,
            data=context.crypto_form_data,
            allow_redirects=True
        )
    elif hasattr(context, 'setup_mode_form_data'):
        context.response = context.session.post(
            current_url,
            data=context.setup_mode_form_data,
            allow_redirects=True
        )
    elif hasattr(context, 'tls_form_data'):
        context.response = context.session.post(
            current_url,
            data=context.tls_form_data,
            allow_redirects=True
        )
    elif hasattr(context, 'backup_form_data'):
        context.response = context.session.post(
            current_url,
            data=context.backup_form_data,
            allow_redirects=True
        )
    elif hasattr(context, 'demo_data_form_data'):
        context.response = context.session.post(
            current_url,
            data=context.demo_data_form_data,
            allow_redirects=True
        )
    elif hasattr(context, 'superuser_form_data'):
        context.response = context.session.post(
            current_url,
            data=context.superuser_form_data,
            allow_redirects=True
        )

    assert context.response.status_code in [HTTP_OK, HTTP_REDIRECT], \
        f'Failed to proceed: {context.response.status_code}'


@then('the wizard should be at the setup mode selection step')
def step_verify_setup_mode_step(context: runner.Context) -> None:
    """Verifies the wizard is at the setup mode selection step.

    Args:
        context: The behave context
    """
    content_lower = context.response.text.lower()
    assert 'mode' in content_lower or \
           'test' in content_lower, \
           'Not at setup mode selection step'


@when('the user selects "{mode}" setup mode option')
def step_select_setup_mode(context: runner.Context, mode: str) -> None:
    """Selects the setup mode.

    Args:
        context: The behave context
        mode: The setup mode to select
    """
    csrf_token = extract_csrf_token(context.response.text)

    context.setup_mode_form_data = {
        'csrfmiddlewaretoken': csrf_token,
        'setup_mode': 'test' if 'test' in mode.lower() else 'production',
    }


@then('the wizard should be at the TLS server credential step')
def step_verify_tls_step(context: runner.Context) -> None:
    """Verifies the wizard is at the TLS server credential step.

    Args:
        context: The behave context
    """
    content_lower = context.response.text.lower()
    assert 'tls' in content_lower or \
           'certificate' in content_lower or \
           'credential' in content_lower, \
           'Not at TLS server credential step'


@when('the user selects "{option}" TLS certificate option')
def step_select_tls_option(context: runner.Context, option: str) -> None:
    """Selects TLS credential option.

    Args:
        context: The behave context
        option: The TLS option to select
    """
    csrf_token = extract_csrf_token(context.response.text)

    context.tls_form_data = {
        'csrfmiddlewaretoken': csrf_token,
        'tls_option': 'generate' if 'generate' in option.lower() else 'import',
    }


@then('the wizard should be at the backup password setup step')
def step_verify_backup_step(context: runner.Context) -> None:
    """Verifies the wizard is at the backup password setup step.

    Args:
        context: The behave context
    """
    content_lower = context.response.text.lower()
    assert 'backup' in content_lower or \
           'password' in content_lower, \
           'Not at backup password setup step'


@when('the user enters backup password "{password}"')
def step_enter_backup_password(context: runner.Context, password: str) -> None:
    """Enters the backup password.

    Args:
        context: The behave context
        password: The backup password to enter
    """
    context.backup_password = password


@when('the user confirms backup password "{password}"')
def step_confirm_backup_password(context: runner.Context, password: str) -> None:
    """Confirms the backup password.

    Args:
        context: The behave context
        password: The backup password confirmation
    """
    csrf_token = extract_csrf_token(context.response.text)

    context.backup_form_data = {
        'csrfmiddlewaretoken': csrf_token,
        'password': context.backup_password,
        'password_confirm': password,
    }


@then('the wizard should be at the demo data step')
def step_verify_demo_data_step(context: runner.Context) -> None:
    """Verifies the wizard is at the demo data step.

    Args:
        context: The behave context
    """
    content_lower = context.response.text.lower()
    assert 'demo' in content_lower or \
           'sample' in content_lower, \
           'Not at demo data step'


@when('the user chooses to skip demo data')
def step_skip_demo_data(context: runner.Context) -> None:
    """Chooses to skip demo data installation.

    Args:
        context: The behave context
    """
    csrf_token = extract_csrf_token(context.response.text)

    context.demo_data_form_data = {
        'csrfmiddlewaretoken': csrf_token,
        'install_demo_data': 'false',
    }


@then('the wizard should be at the superuser creation step')
def step_verify_superuser_step(context: runner.Context) -> None:
    """Verifies the wizard is at the superuser creation step.

    Args:
        context: The behave context
    """
    content_lower = context.response.text.lower()
    assert 'admin' in content_lower or \
           'user' in content_lower or \
           'account' in content_lower, \
           'Not at superuser creation step'


@when('the user creates admin account with username "{username}" and password "{password}"')
def step_create_admin_account(context: runner.Context, username: str, password: str) -> None:
    """Creates the admin user account.

    Args:
        context: The behave context
        username: The admin username
        password: The admin password
    """
    csrf_token = extract_csrf_token(context.response.text)

    context.superuser_form_data = {
        'csrfmiddlewaretoken': csrf_token,
        'username': username,
        'password1': password,
        'password2': password,
    }
    context.admin_username = username
    context.admin_password = password


@when('the user submits the setup wizard')
def step_submit_setup_wizard(context: runner.Context) -> None:
    """Submits the final setup wizard form.

    Args:
        context: The behave context
    """
    context.response = context.client.post(
        context.response.request['PATH_INFO'],
        context.superuser_form_data,
        follow=True
    )

    assert context.response.status_code in [HTTP_OK, HTTP_REDIRECT], \
        f'Failed to submit setup wizard: {context.response.status_code}'


@then('the setup wizard should be completed')
def step_verify_wizard_completed(context: runner.Context) -> None:
    """Verifies the setup wizard has been completed.

    Args:
        context: The behave context
    """
    # Check if we're redirected away from setup wizard
    assert '/setup-wizard/' not in context.response.request['PATH_INFO'], \
        'Still in setup wizard after completion'


@then('the user should be redirected to the login page')
def step_verify_login_redirect(context: runner.Context) -> None:
    """Verifies the user is redirected to the login page.

    Args:
        context: The behave context
    """
    assert '/login' in context.response.request['PATH_INFO'].lower() or \
           b'login' in context.response.content.lower(), \
           'Not redirected to login page'


@when('the user logs in with username "{username}" and password "{password}"')
def step_login_user(context: runner.Context, username: str, password: str) -> None:
    """Logs in with the created admin credentials.

    Args:
        context: The behave context
        username: The username to log in with
        password: The password to log in with
    """
    # Get the login page first
    context.response = context.session.get(f'{context.base_url}/users/login/', allow_redirects=True)
    csrf_token = extract_csrf_token(context.response.text)

    # Submit login form
    login_data = {
        'csrfmiddlewaretoken': csrf_token,
        'username': username,
        'password': password,
    }

    context.response = context.session.post(f'{context.base_url}/users/login/', data=login_data, allow_redirects=True)

    assert context.response.status_code == HTTP_OK, \
        f'Login failed with status: {context.response.status_code}'


@then('the user should successfully access the dashboard')
def step_verify_dashboard_access(context: runner.Context) -> None:
    """Verifies the user can access the dashboard.

    Args:
        context: The behave context
    """
    # Check if we're at a dashboard or authenticated page
    content_lower = context.response.text.lower()
    assert 'logout' in content_lower or \
           'dashboard' in content_lower or \
           'trustpoint' in content_lower, \
           'Failed to access dashboard after login'
