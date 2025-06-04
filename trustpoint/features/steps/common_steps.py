"""File for steps which are used more often across multiple feature files."""

import logging

from behave import given, runner, step, then, when
from django.contrib.auth.models import User
from django.test import Client
from pki.models.domain import DomainModel

HTTP_OK = 200
logger = logging.getLogger(__name__)


@given('the TPC_Web application is running')
def step_tpc_web_running(context: runner.Context) -> None:  # noqa: ARG001
    """Verifies that the TPC_Web application is running.

    This step checks that the TPC_Web application is running and accessible at the expected URL.

    Args:
        context: the behave context
    """
    response = Client().get('/users/login/')
    if response.status_code != HTTP_OK:
        msg = f'{response.status_code} != {HTTP_OK}!'
        raise AssertionError(msg)

@given('a domain with a name {domain_name} exist')
def step_domain_exists(context: runner.Context, domain_name: str) -> None:  # noqa: ARG001
    """.

    Args:
        context: the behave context
        domain_name: a domain name
    """
    domain, created = DomainModel.objects.get_or_create(unique_name=domain_name)
    assert created, f" Domain creation failed"
    assert domain.unique_name == domain_name, f" Domain name mismatch: expected '{domain_name}', got '{domain.name}'"

    context.domain = domain


@step('Commentary')
def commentary_step(context: runner.Context) -> None:
    """Provides annotation "@Commentary" inside feature files for additional text explanation.

    Args:
        context: the behave context
    """
    scenario = context.formatter.current_scenario
    step = scenario.current_step
    step.commentary_override = True


@given('the admin user is logged into TPC_Web')
def step_admin_logged_in(context: runner.Context) -> None:
    """Logs the admin user into the TPC_Web interface.

    This step sets up the initial state for all scenarios, ensuring the admin is authenticated and on the TPC_Web
    dashboard.

    Args:
        context: the behave context
    """
    try:
        User.objects.create_superuser(username='admin', password='testing321')  # noqa: S106
        client = Client()
        login_success = client.login(username='admin', password='testing321')  # noqa: S106
        if not login_success:
            msg = 'Login unsuccessful'
            raise AssertionError(msg)  # noqa: TRY301

        context.authenticated_client = client

        response = client.get('/pki/certificates/')
        if response.status_code != HTTP_OK:
            msg = 'Could not get a HTTP_OK from visiting the certificates page.'
            raise AssertionError(msg)  # noqa: TRY301

    except Exception as error:
        msg = f'Error: {error}'
        raise AssertionError(msg) from error


@then('the system should display a confirmation message stating "{confirm_message}"')
def step_confirmation_message(context: runner.Context, confirm_message: str) -> None:  # noqa: ARG001
    """Verifies that the system displays a success message after an action.

    Args:
        context: the behave context
    """
    html = context.response.content
    #print("html", html)
    assert confirm_message.encode() in html, f"Missing confirmation message, {confirm_message}"


@then('the system should display an error message stating {error_message}')
def step_error_message(context: runner.Context, error_message: str) -> None:  # noqa: ARG001
    """Verifies that the system displays a specific error message.

    Args:
        context: the behave context
        error_message (str): The expected error message text.
    """
    msg = 'Step not implemented: Error message check.'
    raise AssertionError(msg)


@given('an API client is authenticated')
def step_api_client_authenticated(context: runner.Context) -> None:  # noqa: ARG001
    """Authenticates the API client to enable authorized interactions with the REST API.

    Args:
        context: the behave context
    """
    msg = 'Step not implemented: API client authentication.'
    raise AssertionError(msg)


@then('the API response should have a status code of {status_code}')
def step_verify_status_code(context: runner.Context, status_code: str) -> None:  # noqa: ARG001
    """Verifies the API response status code.

    Args:
        context: the behave context
        status_code (str): The expected status code.
    """
    msg = 'Step not implemented: Verify API response status code.'
    raise AssertionError(msg)


@then('the response payload should include an error message stating "{error_message}"')
def step_verify_error_message(context: runner.Context, error_message: str) -> None:  # noqa: ARG001
    """Verifies the response payload includes the specified error message.

    Args:
        context: the behave context
        error_message (str): The expected error message text.
    """
    html = context.response.content
    assert error_message.encode() in html, \
       f"Missing error message, {error_message}"

@when('the admin clicks on "{button_name}"')
def step_when_admin_click_button(context: runner.Context, button_name: str) -> None:  # noqa: ARG001
    """Simulates click on given button.

    Args:
        context: the behave context
        error_message (str): The expected error message text.
    """
    if button_name == "Add new Issuing CA":
        context.response = context.authenticated_client.get("/pki/issuing-cas/add/method-select/")
        # Check that page loaded successfully
        assert context.response.status_code == 200, f"Failed to load Add new Issuing CA page"
    elif button_name == "Import From PKCS#12 File":
        context.response = context.authenticated_client.get("/pki/issuing-cas/add/file-import/pkcs12")
        # Check that page loaded successfully
        assert context.response.status_code == 200, f"Failed to load issuing Add new Issuing CA using pkcs#12 import"
    elif button_name == "Delete selected Issuing CAs":
        context.response = context.authenticated_client.post(
            f"/pki/issuing-cas/delete/{context.issuing_ca.id}/",
            follow=True
        )
    elif button_name == "Import From Separate Key and Certificate Files":
        context.response = context.authenticated_client.get("/pki/issuing-cas/add/file-import/separate-files")
        # Check that page loaded successfully
        assert context.response.status_code == 200, f"Failed to load issuing Add new Issuing CA using import from separate files"
    elif button_name == "Add new Domain":
        context.response = context.authenticated_client.post('/pki/domains/add/', context.domain_add_form_data, follow=True)
        assert context.response.status_code == 200, f"Failed to add new domain."
    elif button_name == "Add new Truststore":
        with open(context.truststore_add_form_data['trust_store_file'], 'rb') as f:
          context.truststore_add_form_data['trust_store_file'] = f
          context.response = context.authenticated_client.post('/pki/truststores/add/', context.truststore_add_form_data, follow=True)
          assert context.response.status_code == 200, f"Failed to add new truststore."
    elif button_name == "Create Device":
        context.response = context.authenticated_client.post('/devices/add/', context.device_add_form_data, follow=True)
        assert context.response.status_code == 200, f"Failed to add new device."
    else:
        msg = 'Step not implemented: Verify API response status code.'
        raise AssertionError(msg)


@when('the admin navigates to the "{page_name}" page')
def step_navigate_add_device(context: runner.Context, page_name: str) -> None:  # noqa: ARG001
    """Navigates to the given page.

    Args:
        context (runner.Context): Behave context.
        page_name (str): Page name.
    """
    if page_name == "Add Device":
        context.response = context.authenticated_client.get("/devices/add/")
    elif page_name == "device list":
        context.response = context.authenticated_client.get("/devices/")
    elif page_name == "truststore list":
        context.response = context.authenticated_client.get("/pki/truststores/")
    elif page_name == "Add new Domain":
        context.response = context.authenticated_client.get("/pki/domains/add/")
    elif page_name == "domain list":
        context.response = context.authenticated_client.get("/pki/domains/")
    elif page_name == "Add new Truststore":
        context.response = context.authenticated_client.get("/pki/truststores/add/")
    else:
        msg = 'Page name is not valid.'
        raise AssertionError(msg)
    assert context.response.status_code == 200, f"Failed to load {page_name} page"

        
    

