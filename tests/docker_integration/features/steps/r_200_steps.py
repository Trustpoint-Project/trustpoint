"""Python steps file for R_200 - Docker Setup Wizard test."""

from __future__ import annotations

import re
import time

import requests
from behave import given, runner, then, when

# Disable SSL warnings for self-signed certificates
requests.packages.urllib3.disable_warnings(  # type: ignore[attr-defined]
    requests.packages.urllib3.exceptions.InsecureRequestWarning  # type: ignore[attr-defined]
)

HTTP_OK = 200
HTTP_REDIRECT = 302
DOCKER_URL = 'https://localhost'


def extract_csrf_token(html_content: str) -> str:
    """Extract CSRF token from HTML content."""
    patterns = [
        r'name=["\']csrfmiddlewaretoken["\']\s+value=["\']([^"\']+)["\']',
        r'name="csrfmiddlewaretoken"\s+value="([^"]+)"',
        r'value=["\']([^"\']+)["\']\s+name=["\']csrfmiddlewaretoken["\']',
        r'name=["\']csrfmiddlewaretoken["\'][^>]*value=["\']([^"\']+)["\']',
    ]
    for pattern in patterns:
        match = re.search(pattern, html_content, re.IGNORECASE)
        if match:
            return match.group(1)
    msg = 'CSRF token not found in response'
    raise AssertionError(msg)


def find_link_url(html_content: str, link_text: str) -> str | None:
    """Find a link URL by its text content."""
    pattern = rf'href=["\']([^"\']+)["\'][^>]*>[^<]*{re.escape(link_text)}'
    match = re.search(pattern, html_content, re.IGNORECASE | re.DOTALL)
    if match:
        return match.group(1)
    return None


def check_for_errors(html_content: str, url: str) -> None:
    """Check for error messages in the HTML content.

    Looks for common Django error patterns and Bootstrap alert-danger elements.

    Args:
        html_content: The HTML content to check
        url: The current URL (for error messages)

    Raises:
        AssertionError: If any error is found on the page
    """
    from bs4 import BeautifulSoup

    # Check for visible alert-danger (Bootstrap errors)
    soup = BeautifulSoup(html_content, "html.parser")
    for alert in soup.find_all(class_="alert-danger"):
        style = alert.get("style", "")
        classes = alert.get("class", [])
        if "display: none" in style or "tp-d-none" in classes or "d-none" in classes:
            continue
        error_content = alert.get_text(strip=True)
        if error_content:
            raise AssertionError(f"Alert danger message found on page {url}: {error_content[:200]}")

    # Django form errors
    if soup.find("ul", class_="errorlist"):
        raise AssertionError(f"Form validation error found on page {url}")

    # Django messages framework errors (visible only)
    for error_div in soup.find_all(class_=lambda c: c and "error" in c):
        style = error_div.get("style", "")
        classes = error_div.get("class", [])
        if "display: none" in style or "tp-d-none" in classes or "d-none" in classes:
            continue
        error_content = error_div.get_text(strip=True)
        if error_content:
            raise AssertionError(f"Error message found on page {url}: {error_content[:200]}")

    # HTTP 500/404 error page or Django debug page
    if re.search(r'Server Error \(500\)', html_content, re.IGNORECASE):
        raise AssertionError(f"Server Error 500 found on page {url}")
    if re.search(r'Page not found \(404\)', html_content, re.IGNORECASE):
        raise AssertionError(f"Page not found 404 on page {url}")
    if re.search(r'<title>([^<]*Exception[^<]*)</title>', html_content, re.IGNORECASE):
        raise AssertionError(f"Exception in title found on page {url}")
    if re.search(r'<title>([^<]*Error[^<]*)</title>', html_content, re.IGNORECASE):
        raise AssertionError(f"Error in title found on page {url}")


@given('a fresh Trustpoint Docker container is running')
def step_docker_container_running(context: runner.Context) -> None:
    """Verify the Docker container is accessible."""
    context.session = requests.Session()
    context.session.verify = False
    context.base_url = DOCKER_URL
    context.session.headers.update({
        'Referer': DOCKER_URL,
        'Origin': DOCKER_URL,
    })
    max_retries = 30
    for attempt in range(max_retries):
        try:
            response = context.session.get(context.base_url, timeout=5)
            if response.status_code in [HTTP_OK, HTTP_REDIRECT]:
                return
        except Exception:  # noqa: BLE001
            if attempt < max_retries - 1:
                time.sleep(2)
            else:
                msg = 'Docker container not accessible after maximum retries'
                raise AssertionError(msg) from None


@when('the user accesses the setup wizard')
def step_access_setup_wizard(context: runner.Context) -> None:
    """Access the setup wizard landing page."""
    context.response = context.session.get(f'{context.base_url}/', allow_redirects=True)
    assert context.response.status_code == HTTP_OK, \
        f'Failed to access setup wizard: {context.response.status_code}'


@then('the wizard should be at the crypto storage setup step')
def step_verify_crypto_storage_step(context: runner.Context) -> None:
    """Verify the wizard is at the crypto storage selection step."""
    check_for_errors(context.response.text, context.response.url)
    content = context.response.text.lower()
    assert 'crypto' in content or 'storage' in content, \
        f'Not at crypto storage step. URL: {context.response.url}'


@when('the user selects "{storage_type}" as crypto storage')
def step_select_crypto_storage(context: runner.Context, storage_type: str) -> None:
    """Select the crypto storage type."""
    storage_mapping = {
        'file system': 'software',
        'software': 'software',
        'softhsm': 'softhsm',
        'physical hsm': 'physical_hsm',
    }
    context.selected_storage = storage_mapping.get(storage_type.lower(), 'software')


@when('the user submits the form')
def step_submit_form(context: runner.Context) -> None:
    """Submit the current form."""
    csrf_token = extract_csrf_token(context.response.text)
    current_url = context.response.url
    form_data = {'csrfmiddlewaretoken': csrf_token}
    if hasattr(context, 'selected_storage'):
        form_data['storage_type'] = context.selected_storage
        delattr(context, 'selected_storage')
    context.response = context.session.post(current_url, data=form_data, allow_redirects=True)
    assert context.response.status_code in [HTTP_OK, HTTP_REDIRECT], \
        f'Form submission failed: {context.response.status_code}'


@then('the wizard should be at the setup mode step')
def step_verify_setup_mode_step(context: runner.Context) -> None:
    """Verify the wizard is at the setup mode selection step."""
    check_for_errors(context.response.text, context.response.url)
    content = context.response.text.lower()
    assert 'setup mode' in content or 'fresh' in content or 'restore' in content, \
        f'Not at setup mode step. URL: {context.response.url}'


@when('the user clicks "{button_text}"')
def step_click_button(context: runner.Context, button_text: str) -> None:
    """Click a button or link with the given text."""
    html = context.response.text
    current_url = context.response.url

    # First, try to find a link with this text
    link_url = find_link_url(html, button_text)
    if link_url:
        if not link_url.startswith('http'):
            link_url = f'{context.base_url}{link_url}'
        context.response = context.session.get(link_url, allow_redirects=True)
        assert context.response.status_code == HTTP_OK, \
            f'Failed to follow link: {context.response.status_code}'
        return

    # If no link found, try to find and submit a form button
    csrf_token = extract_csrf_token(html)
    form_data = {'csrfmiddlewaretoken': csrf_token}

    # Map button text to form field names
    button_mapping = {
        'generate certificate': 'generate_credential',
        'import certificate': 'import_credential',
        'apply tls configuration': None,
        'continue with demo data': 'with-demo-data',
        'continue without demo data': 'without-demo-data',
        'create super-user': None,
    }

    button_key = button_text.lower()
    if button_key in button_mapping:
        button_name = button_mapping[button_key]
        if button_name:
            form_data[button_name] = ''

    context.response = context.session.post(current_url, data=form_data, allow_redirects=True)
    assert context.response.status_code in [HTTP_OK, HTTP_REDIRECT], \
        f'Button click failed: {context.response.status_code}'


@then('the wizard should be at the TLS server credential selection step')
def step_verify_tls_selection_step(context: runner.Context) -> None:
    """Verify the wizard is at the TLS credential selection step."""
    check_for_errors(context.response.text, context.response.url)
    content = context.response.text.lower()
    assert 'tls' in content, f'Not at TLS selection step. URL: {context.response.url}'
    assert 'generate' in content or 'import' in content, \
        f'Missing generate/import options. URL: {context.response.url}'


@then('the wizard should be at the TLS certificate generation step')
def step_verify_tls_generation_step(context: runner.Context) -> None:
    """Verify the wizard is at the TLS certificate generation step."""
    check_for_errors(context.response.text, context.response.url)
    content = context.response.text.lower()
    assert 'san' in content or 'subject alternative' in content or 'generate' in content, \
        f'Not at TLS generation step. URL: {context.response.url}'


@when('the user submits the SAN form with default values')
def step_submit_san_form(context: runner.Context) -> None:
    """Submit the SAN form with default values."""
    csrf_token = extract_csrf_token(context.response.text)
    current_url = context.response.url
    form_data = {
        'csrfmiddlewaretoken': csrf_token,
        'ipv4_addresses': '127.0.0.1',
        'ipv6_addresses': '::1',
        'domain_names': 'localhost',
    }
    context.response = context.session.post(current_url, data=form_data, allow_redirects=True)
    assert context.response.status_code in [HTTP_OK, HTTP_REDIRECT], \
        f'SAN form submission failed: {context.response.status_code}'


@then('the wizard should be at the TLS apply step')
def step_verify_tls_apply_step(context: runner.Context) -> None:
    """Verify the wizard is at the TLS apply step."""
    check_for_errors(context.response.text, context.response.url)
    content = context.response.text.lower()
    assert 'apply' in content or 'download' in content or 'trust' in content, \
        f'Not at TLS apply step. URL: {context.response.url}'


@when('the user waits for the server to restart')
def step_wait_for_server_restart(context: runner.Context) -> None:
    """Wait for the server to restart after TLS configuration."""
    time.sleep(5)
    max_retries = 30
    for attempt in range(max_retries):
        try:
            context.response = context.session.get(
                f'{context.base_url}/setup-wizard/demo-data/',
                timeout=10,
                allow_redirects=True
            )
            if context.response.status_code == HTTP_OK:
                return
        except Exception:  # noqa: BLE001
            if attempt < max_retries - 1:
                time.sleep(2)
    msg = 'Server did not restart in time'
    raise AssertionError(msg)


@then('the wizard should be at the demo data step')
def step_verify_demo_data_step(context: runner.Context) -> None:
    """Verify the wizard is at the demo data step."""
    check_for_errors(context.response.text, context.response.url)
    content = context.response.text.lower()
    assert 'demo' in content or 'data' in content, \
        f'Not at demo data step. URL: {context.response.url}'


@then('the wizard should be at the superuser creation step')
def step_verify_superuser_step(context: runner.Context) -> None:
    """Verify the wizard is at the superuser creation step."""
    check_for_errors(context.response.text, context.response.url)
    content = context.response.text.lower()
    assert 'super' in content or 'user' in content or 'admin' in content, \
        f'Not at superuser creation step. URL: {context.response.url}'


@when('the user creates a superuser with username "{username}" and password "{password}"')
def step_create_superuser(context: runner.Context, username: str, password: str) -> None:
    """Create a superuser account."""
    csrf_token = extract_csrf_token(context.response.text)
    current_url = context.response.url
    form_data = {
        'csrfmiddlewaretoken': csrf_token,
        'username': username,
        'password1': password,
        'password2': password,
    }
    context.response = context.session.post(current_url, data=form_data, allow_redirects=True)
    context.admin_username = username
    context.admin_password = password
    assert context.response.status_code in [HTTP_OK, HTTP_REDIRECT], \
        f'Superuser creation failed: {context.response.status_code}'


@then('the setup should be complete')
def step_verify_setup_complete(context: runner.Context) -> None:
    """Verify the setup wizard is complete."""
    check_for_errors(context.response.text, context.response.url)
    assert 'setup-wizard' not in context.response.url.lower(), \
        f'Still in setup wizard. URL: {context.response.url}'


@then('the user should be redirected to the login page')
def step_verify_login_redirect(context: runner.Context) -> None:
    """Verify the user is redirected to the login page."""
    check_for_errors(context.response.text, context.response.url)
    url = context.response.url.lower()
    content = context.response.text.lower()
    assert 'login' in url or 'login' in content, \
        f'Not redirected to login page. URL: {context.response.url}'


@when('the user logs in with username "{username}" and password "{password}"')
def step_login_user(context: runner.Context, username: str, password: str) -> None:
    """Log in with the given credentials."""
    login_url = f'{context.base_url}/users/login/'
    context.response = context.session.get(login_url, allow_redirects=True)
    csrf_token = extract_csrf_token(context.response.text)
    login_data = {
        'csrfmiddlewaretoken': csrf_token,
        'username': username,
        'password': password,
    }
    context.response = context.session.post(login_url, data=login_data, allow_redirects=True)
    assert context.response.status_code == HTTP_OK, \
        f'Login failed: {context.response.status_code}'


@then('the user should successfully access the dashboard')
def step_verify_dashboard_access(context: runner.Context) -> None:
    """Verify the user can access the dashboard."""
    check_for_errors(context.response.text, context.response.url)
    content = context.response.text.lower()
    assert 'logout' in content or 'dashboard' in content or 'trustpoint' in content, \
        'Failed to access dashboard after login'


@when('the user navigates to "{path}"')
def step_navigate_to_path(context: runner.Context, path: str) -> None:
    """Navigate to a specific path."""
    url = f'{context.base_url}{path}'
    context.response = context.session.get(url, allow_redirects=True)
    assert context.response.status_code == HTTP_OK, \
        f'Failed to navigate to {path}: {context.response.status_code}'


@then('the page should load without errors')
def step_verify_page_loads_without_errors(context: runner.Context) -> None:
    """Verify the current page loads without any errors."""
    check_for_errors(context.response.text, context.response.url)
    assert context.response.status_code == HTTP_OK, \
        f'Page returned error status: {context.response.status_code}'


@then('the page should contain "{text}"')
def step_verify_page_contains(context: runner.Context, text: str) -> None:
    """Verify the page contains specific text."""
    check_for_errors(context.response.text, context.response.url)
    assert text.lower() in context.response.text.lower(), \
        f'Page does not contain "{text}". URL: {context.response.url}'


@when('the user fills the device form with:')
def step_fill_device_form(context: runner.Context) -> None:
    """Fill the device creation form with provided table data."""
    context.device_form = {row['name']: row['value'] for row in context.table}


@when('the user enables CMP shared secret')
def step_enable_cmp_shared_secret(context: runner.Context) -> None:
    context.device_form = getattr(context, 'device_form', {})
    context.device_form['no_onboarding_pki_protocols'] = context.device_form.get('no_onboarding_pki_protocols', [])
    context.device_form['no_onboarding_pki_protocols'].append('1')  # CMP - Shared Secret (HMAC)


@when('the user enables EST username password')
def step_enable_est_username_password(context: runner.Context) -> None:
    context.device_form = getattr(context, 'device_form', {})
    context.device_form['no_onboarding_pki_protocols'] = context.device_form.get('no_onboarding_pki_protocols', [])
    context.device_form['no_onboarding_pki_protocols'].append('4')  # EST - Username & Password


@when('the user enables Manual enrollment')
def step_enable_manual_enrollment(context: runner.Context) -> None:
    context.device_form = getattr(context, 'device_form', {})
    context.device_form['no_onboarding_pki_protocols'] = context.device_form.get('no_onboarding_pki_protocols', [])
    context.device_form['no_onboarding_pki_protocols'].append('16')  # Manual


@when('the user submits the device form')
def step_submit_device_form(context: runner.Context) -> None:
    """Submit the device creation form."""
    csrf_token = extract_csrf_token(context.response.text)
    current_url = context.response.url

    # For Django multiple checkboxes, we need to send the values as a list
    protocols = context.device_form.get('no_onboarding_pki_protocols', ['1', '4', '16'])
    final_form_data = [
        ('csrfmiddlewaretoken', csrf_token),
        ('common_name', context.device_form.get('name', 'TestDevice01')),
        ('serial_number', '123456'),
        ('domain', '1'),  # arburg domain
    ]

    # Add each PKI protocol as a separate tuple
    for value in protocols:
        final_form_data.append(('no_onboarding_pki_protocols', value))

    context.response = context.session.post(current_url, data=final_form_data, allow_redirects=True)
    assert context.response.status_code in [HTTP_OK, HTTP_REDIRECT], \
        f'Device form submission failed: {context.response.status_code}'


@then('the device should be created successfully')
def step_device_created_successfully(context: runner.Context) -> None:
    check_for_errors(context.response.text, context.response.url)
    assert 'Device created' in context.response.text or 'Devices' in context.response.text, \
        'Device creation confirmation not found.'


@then('the device should have PKI protocols enabled:')
def step_device_has_pki_protocols(context: runner.Context) -> None:
    for row in context.table:
        assert row['protocol'] in context.response.text, f"Protocol {row['protocol']} not found in device details."
