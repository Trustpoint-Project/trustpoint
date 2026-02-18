"""Python steps file for R_001."""

from behave import given, runner, then, when
from django.middleware.csrf import get_token
from pki.models.domain import DomainModel
from devices.models import DeviceModel
from bs4 import BeautifulSoup


@given('the device {name} with {serial_number} exists')
def step_device_exists(context: runner.Context, name: str, serial_number: str) -> None:  # noqa: ARG001
    """Ensures that an device with the specified name and serial_number exists in the system.

    Args:
        context (runner.Context): Behave context.
        name (str): The name of the device.
        serial_number (str): The Serial number of the device.
    """

    context.device, created = DeviceModel.objects.get_or_create(
        common_name=name, serial_number=serial_number, domain=context.domain
    )
    assert created, f' Device creation failed'
    assert context.device.common_name == name, f"Device {name} with serial number {serial_number} doesn't exist"


@when('the admin fills in the device details with {name}, {serial_number} and domain "{domain_name}"')
def step_fill_device_details(context: runner.Context, name: str, serial_number: str, domain_name: str) -> None:  # noqa: ARG001
    """Fills in the device creation form.

    Args:
        context (runner.Context): Behave context.
        name (str): The name of the device.
        serial_number (str): The Serial number of the device.
    """
    # Retrieve CSRF token
    csrf_token = get_token(context.response.wsgi_request)

    domain = DomainModel.objects.get(unique_name=domain_name)

    assert domain.unique_name == domain_name, f"Domain {domain_name} doesn't exist"
    # Prepare POST data
    context.device_add_form_data = {
        'csrfmiddlewaretoken': csrf_token,
        'common_name': name,
        'serial_number': serial_number,
        'domain': domain.id,
        'onboarding_protocol': '2',
        'onboarding_pki_protocols': ['1'],
        '_save': 'Save',
    }


@then('the system should display a confirmation page')
def step_device_list(context: runner.Context) -> None:  # noqa: ARG001
    """Verifies that the new device appears in the device list.

    Args:
        context (runner.Context): Behave context.
        name (str): The name of the device.
        serial_number (str): The Serial number of the device.
    """
    assert context.response.status_code == 200, 'Device add form submission failed'


@then('the new device with {name}, {serial_number} and domain name "{domain_name}" should appear in the device list')
def step_device_list(context: runner.Context, name: str, serial_number: str, domain_name: str) -> None:  # noqa: ARG001
    """Verifies that the new device appears in the device list.

    Args:
        context (runner.Context): Behave context.
        name (str): The name of the device.
        serial_number (str): The Serial number of the device.
    """
    context.response = context.authenticated_client.get('/devices/')
    soup = BeautifulSoup(context.response.content, 'html.parser')
    # Find all <td> elements
    tds = soup.find_all('td')

    # Get their text content (unescaped and stripped)
    values = [td.get_text(strip=True) for td in tds]

    assert name in values, f"Device {name} doesn't exist"
    assert serial_number in values, f"Device with serial number {serial_number} doesn't exist"
    assert domain_name in values, f"Domain {domain_name} doesn't exist"


@when('the admin deletes the device with the name {name}')
def step_delete_device(context: runner.Context, name: str) -> None:  # noqa: ARG001
    """Deletes an device by name.

    Args:
        context (runner.Context): Behave context.
        name (str): The name of the device to be deleted.
    """

    context.response = context.authenticated_client.get(
        '/devices/delete-device/' + str(context.device.id), follow=True, HTTP_X_REQUESTED_WITH='XMLHttpRequest'
    )

    assert context.response.status_code == 200, 'Device delete form submission failed'
    assert b'Confirm Device Deletion' in context.response.content
    context.response = context.authenticated_client.post(
        '/devices/delete-device', data={'pks': str(context.device.id)}, follow=True
    )
    assert context.response.status_code == 200, 'Device deletion response'
    assert not DeviceModel.objects.filter(id=context.device.id).exists(), 'Device deletion failed'


@then('the device {name} should no longer appear in the device list')
def step_verify_device_deletion(context: runner.Context, name: str) -> None:  # noqa: ARG001
    """Verifies that the device no longer appears in the list.

    Args:
        context (runner.Context): Behave context.
        name (str): The name of the device.
    """
    assert name not in context.response, 'Device still exist in the list'


@when('the admin attempts to view the details of a non-existent device {non_existent_device_id}')
def step_attempt_view_nonexistent(context: runner.Context, non_existent_device_id: str) -> None:  # noqa: ARG001
    """Attempts to view details of a non-existent device.

    Args:
        context (runner.Context): Behave context.
        non_existent_device_id (str): The id a non-existent device.
    """
    # Navigate (GET request) to the device detailed page
    context.response = context.authenticated_client.get(f'/devices/details/{non_existent_device_id}')


@then('the system should display an error message')
def step_device_list(context: runner.Context) -> None:  # noqa: ARG001
    """Verifies that the new device appears in the device list.

    Args:
        context (runner.Context): Behave context.
    """
    assert context.response.status_code == 404, f'Expected 404 Not Found, but got {context.response.status_code}'
