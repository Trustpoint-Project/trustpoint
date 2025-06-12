"""Python steps file for R_001."""

from behave import given, runner, then, when
from pki.models import TruststoreModel
from bs4 import BeautifulSoup
import os


@given('a truststore {truststore_name} with {intended_usage} exist')
def step_truststore_exists(context: runner.Context, truststore_name: str, intended_usage: str) -> None:  # noqa: ARG001
    """.

    Args:
        context: Behave context.
        truststore_name (str): The name of the truststore.
        intended_usage (str): The intended usage of the truststore.
    """
    truststore_file_path = os.path.abspath(f"../tests/data/trust-store/trust_store.pem")
    usage = 0
    if intended_usage == "TLS":
        usage = 1
    elif intended_usage == "Generic":
        usage = 2
    with open(truststore_file_path, 'rb') as f:
      # Prepare POST data
      truststore_add_form_data = {
        'unique_name': truststore_name,
        'intended_usage': usage,
        'trust_store_file': f,
      }
      context.response = context.authenticated_client.post('/pki/truststores/add/', truststore_add_form_data, follow=True)
      assert context.response.status_code == 200, f"Failed to add new truststore."
      context.truststore = TruststoreModel.objects.get(unique_name=truststore_name)

@when('the admin fills in the truststore details with {name}, {intended_usage} and {file_type}')
def step_fill_truststore_details(context: runner.Context, name: str, intended_usage: str, file_type: str) -> None:  # noqa: ARG001
    """Fills in the truststore creation form.

    Args:
        context (runner.Context): Behave context.
        name (str): The name of the truststore.
        intended_usage (str): The intended usage of the truststore.
        file_type (str): The file type of the truststore.
    """
    truststore_file_path = os.path.abspath(f"../tests/data/trust-store/trust_store{file_type}")
    usage = 0
    if intended_usage == "TLS":
        usage = 1
    elif intended_usage == "Generic":
        usage = 2

    # Prepare POST data
    context.truststore_add_form_data = {
      'unique_name': name,
      'intended_usage': usage,
      'trust_store_file': truststore_file_path,
    }
@then('the new truststore with {name} and {intended_usage} should appear in the truststore list')
def step_truststore_list(context: runner.Context, name: str, intended_usage: str) -> None:  # noqa: ARG001
    """Verifies that the new truststore appears in the truststore list.

    Args:
        context (runner.Context): Behave context.
        name (str): The name of the truststore.
        intended_usage (str): The intended usage of the truststore.
    """
    soup = BeautifulSoup(context.response.content, "html.parser")

    # Find all <td> elements
    tds = soup.find_all("td")

    # Get their text content (unescaped and stripped)
    values = [td.get_text(strip=True) for td in tds]

    assert name in values, f"Truststore {name} doesn't exist"
    assert intended_usage in values, f"Intended usage {intended_usage} doesn't exist"


@when('the admin deletes the truststore with the name {name}')
def step_delete_truststore(context: runner.Context, name: str) -> None:  # noqa: ARG001
    """Deletes an truststore by name.

    Args:
        context (runner.Context): Behave context.
        name (str): The name of the truststore to be deleted.
    """

    context.response = context.authenticated_client.get(
        '/pki/truststores/delete/'+ str(context.truststore.id),
        follow=True,
        HTTP_X_REQUESTED_WITH="XMLHttpRequest"
    )

    assert context.response.status_code == 200, "Truststore delete form submission failed"
    assert b"Confirm Truststore Deletion" in context.response.content
    context.response = context.authenticated_client.post(f"/pki/truststores/delete/{context.truststore.id}/", data={}, follow=True)
    assert context.response.status_code == 200, "Truststore deletion response"
    assert not TruststoreModel.objects.filter(id=context.truststore.id).exists(), f"Deletion of Truststore with name {name} failed"


@then('the truststore {name} should no longer appear in the truststore list')
def step_verify_truststore_deletion(context: runner.Context, name: str) -> None:  # noqa: ARG001
    """Verifies that the truststore no longer appears in the list.

    Args:
        context (runner.Context): Behave context.
        name (str): The name of the truststore.
    """
    assert name not in context.response, f"Truststore with name {name} still exist in the list"


@when('the admin attempts to view the details of a non-existent truststore {non_existent_truststore_id}')
def step_attempt_view_nonexistent(context: runner.Context, non_existent_truststore_id: str) -> None:  # noqa: ARG001
    """Attempts to view details of a non-existent truststore.

    Args:
        context (runner.Context): Behave context.
        non_existent_truststore_id (str): The id a non-existent truststore.
    """
    #Navigate (GET request) to the truststore detailed page
    context.response = context.authenticated_client.get(f"/pki/truststores/config/{non_existent_truststore_id}")