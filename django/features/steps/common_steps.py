"""File for steps which are used more often across multiple feature files."""  # noqa: INP001

import logging

from behave import given, runner, step, then
from django.contrib.auth.models import User
from django.test import Client

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
    assert response.status_code == HTTP_OK


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
        assert login_success, 'Login unsuccessful'
        context.authenticated_client = client

        response = client.get('/pki/certificates/')
        assert response.status_code == HTTP_OK, 'Could not get a HTTP_OK from visiting the certificates page.'
    except Exception as error:  # noqa: BLE001
        assert False, f'Error: {error}'  # noqa: PT015, PT017, B011


@then('the system should display a confirmation message')
def step_confirmation_message(context: runner.Context) -> None:  # noqa: ARG001
    """Verifies that the system displays a success message after an action.

    Args:
        context: the behave context
    """
    assert False, 'Step not implemented: Confirmation message check.'  # noqa: PT015, B011


@then('the system should display an error message stating {error_message}')
def step_error_message(context: runner.Context, error_message: str) -> None:  # noqa: ARG001
    """Verifies that the system displays a specific error message.

    Args:
        context: the behave context
        error_message (str): The expected error message text.
    """
    assert False, 'Step not implemented: Error message check.'  # noqa: PT015, B011


@given('an API client is authenticated')
def step_api_client_authenticated(context: runner.Context) -> None:  # noqa: ARG001
    """Authenticates the API client to enable authorized interactions with the REST API.

    Args:
        context: the behave context
    """
    assert False, 'Step not implemented: API client authentication.'  # noqa: PT015, B011


@then('the API response should have a status code of {status_code}')
def step_verify_status_code(context: runner.Context, status_code: str) -> None:  # noqa: ARG001
    """Verifies the API response status code.

    Args:
        context: the behave context
        status_code (str): The expected status code.
    """
    assert False, 'Step not implemented: Verify API response status code.'  # noqa: PT015, B011


@then('the response payload should include an error message stating {error_message}')
def step_verify_error_message(context: runner.Context, error_message: str) -> None:  # noqa: ARG001
    """Verifies the response payload includes the specified error message.

    Args:
        context: the behave context
        error_message (str): The expected error message text.
    """
    assert False, 'Step not implemented: Verify error message in response payload.'  # noqa: PT015, B011
