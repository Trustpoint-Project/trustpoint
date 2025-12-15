"""Python steps file for R_200 - Docker Setup Wizard test."""

from __future__ import annotations

import re
import time

import requests
from behave import given, runner, then, when

# Disable SSL warnings for self-signed certificates
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)  # type: ignore[attr-defined]

HTTP_OK = 200
HTTP_REDIRECT = 302
DOCKER_URL = 'https://localhost'


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
    # Disable SSL verification for self-signed certificates
    context.session.verify = False
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
    assert 'cryptographic storage configuration' in content_lower or \
           ('storage' in content_lower and 'software' in content_lower), \
           f'Not at crypto storage setup step. URL: {context.response.url}'


@when('the user selects "{storage_type}" as crypto storage')
def step_select_crypto_storage(context: runner.Context, storage_type: str) -> None:
    """Selects the crypto storage type.

    Args:
        context: The behave context
        storage_type: The type of crypto storage to select
    """
    csrf_token = extract_csrf_token(context.response.text)

    # Map user-friendly names to actual form values
    storage_mapping = {
        'file system': 'software',
        'software': 'software',
        'softhsm': 'softhsm',
        'physical hsm': 'physical_hsm',
    }
    
    storage_value = storage_mapping.get(storage_type.lower(), 'software')

    context.crypto_form_data = {
        'csrfmiddlewaretoken': csrf_token,
        'storage_type': storage_value,
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
        delattr(context, 'crypto_form_data')  # Clean up after submission
    elif hasattr(context, 'setup_mode_form_data'):
        # Setup mode uses links, not forms - this is a no-op
        # The navigation already happened in step_select_setup_mode
        if hasattr(context, 'setup_mode_form_data'):
            delattr(context, 'setup_mode_form_data')
    elif hasattr(context, 'tls_form_data'):
        context.response = context.session.post(
            current_url,
            data=context.tls_form_data,
            allow_redirects=True
        )
        delattr(context, 'tls_form_data')
        
        # After applying TLS configuration, the server restarts with a new certificate
        # We need to wait for the server to come back up and re-establish connection
        time.sleep(5)  # Give server time to restart
        
        # Re-establish connection by making a new request (accepting the new certificate)
        max_retries = 30
        for attempt in range(max_retries):
            try:
                context.response = context.session.get(f'{context.base_url}/setup-wizard/', timeout=5, allow_redirects=True)
                if context.response.status_code == HTTP_OK:
                    break
            except Exception:  # noqa: BLE001
                if attempt < max_retries - 1:
                    time.sleep(2)
                else:
                    msg = 'Could not reconnect after TLS configuration'
                    raise AssertionError(msg) from None
    elif hasattr(context, 'backup_form_data'):
        context.response = context.session.post(
            current_url,
            data=context.backup_form_data,
            allow_redirects=True
        )
        delattr(context, 'backup_form_data')
    elif hasattr(context, 'demo_data_form_data'):
        context.response = context.session.post(
            current_url,
            data=context.demo_data_form_data,
            allow_redirects=True
        )
        delattr(context, 'demo_data_form_data')
    elif hasattr(context, 'superuser_form_data'):
        context.response = context.session.post(
            current_url,
            data=context.superuser_form_data,
            allow_redirects=True
        )
        delattr(context, 'superuser_form_data')

    assert context.response.status_code in [HTTP_OK, HTTP_REDIRECT], \
        f'Failed to proceed: {context.response.status_code}'


@then('the wizard should be at the setup mode selection step')
def step_verify_setup_mode_step(context: runner.Context) -> None:
    """Verifies the wizard is at the setup mode selection step.

    Args:
        context: The behave context
    """
    content_lower = context.response.text.lower()
    assert 'setup mode' in content_lower or \
           ('setup' in content_lower and 'scratch' in content_lower), \
           'Not at setup mode selection step'


@when('the user selects "{mode}" setup mode option')
def step_select_setup_mode(context: runner.Context, mode: str) -> None:
    """Selects the setup mode by clicking the appropriate link.

    Args:
        context: The behave context
        mode: The setup mode to select
    """
    # The setup mode page has links, not a form
    # "Setup with Test Mode" or similar means "Start Fresh Setup"
    # Extract the link URL from the page
    if 'test' in mode.lower() or 'fresh' in mode.lower() or 'scratch' in mode.lower():
        # Look for the "Start Fresh Setup" link
        match = re.search(r'href="(/setup-wizard/select_tls_server_credential/)"', context.response.text)
        if match:
            url = match.group(1)
            context.response = context.session.get(f'{context.base_url}{url}', allow_redirects=True)
        else:
            msg = 'Could not find fresh setup link'
            raise AssertionError(msg)
    else:
        # Restore from backup option
        match = re.search(r'href="(/setup-wizard/restore_options/)"', context.response.text)
        if match:
            url = match.group(1)
            context.response = context.session.get(f'{context.base_url}{url}', allow_redirects=True)
        else:
            msg = 'Could not find restore backup link'
            raise AssertionError(msg)


@then('the wizard should be at the TLS server credential step')
def step_verify_tls_step(context: runner.Context) -> None:
    """Verifies the wizard is at the TLS server credential step.

    Args:
        context: The behave context
    """
    content_lower = context.response.text.lower()
    assert 'configure tls-server credential' in content_lower or \
           ('tls' in content_lower and 'certificate' in content_lower), \
           'Not at TLS server credential step'


@when('the user selects "{option}" TLS certificate option')
def step_select_tls_option(context: runner.Context, option: str) -> None:
    """Selects TLS credential option and completes the generation/import process.

    Args:
        context: The behave context
        option: The TLS option to select
    """
    current_url = context.response.url
    csrf_token = extract_csrf_token(context.response.text)

    # The form has buttons with different names: generate_credential or import_credential
    if 'generate' in option.lower() or 'self-signed' in option.lower():
        button_name = 'generate_credential'
        
        # Step 1: Click "Generate Certificate" button
        context.response = context.session.post(
            current_url,
            data={
                'csrfmiddlewaretoken': csrf_token,
                button_name: '',
            },
            allow_redirects=True
        )
        
        # Step 2: Submit the SAN form (uses default values)
        csrf_token = extract_csrf_token(context.response.text)
        context.response = context.session.post(
            context.response.url,
            data={
                'csrfmiddlewaretoken': csrf_token,
                'ipv4_addresses': '127.0.0.1',
                'ipv6_addresses': '::1',
                'domain_names': 'localhost',
            },
            allow_redirects=True
        )
        
        # Step 3: Submit "Apply TLS configuration" form
        csrf_token = extract_csrf_token(context.response.text)
        context.tls_form_data = {
            'csrfmiddlewaretoken': csrf_token,
        }
    else:
        # Import credential flow (not fully implemented in this test)
        button_name = 'import_credential'
        context.tls_form_data = {
            'csrfmiddlewaretoken': csrf_token,
            button_name: '',
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
        'without-demo-data': '',  # Button name for skipping demo data
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
