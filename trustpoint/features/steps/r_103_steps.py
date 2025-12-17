"""Python steps file for R_103."""

from behave import given, runner, then, when
from pki.models import IssuingCaModel, DomainModel
from bs4 import BeautifulSoup


@given('a domain {domain_name} with issuing ca "{ca_name}" exist')
def step_domain_exists(context: runner.Context, domain_name: str, ca_name: str) -> None:  # noqa: ARG001
    """.

    Args:
        context: the behave context.
        domain_name: The name of the domain.
        ca_name: The name of the issuing ca.
    """
    issuing_ca = IssuingCaModel.objects.get(unique_name=ca_name)
    assert issuing_ca.unique_name == ca_name, f"Issuing CA with name {ca_name} not found"
    
    domain, created = DomainModel.objects.get_or_create(unique_name=domain_name)
    assert created, f" Domain creation failed"
    assert domain.unique_name == domain_name, f" Domain name mismatch: expected '{domain_name}', got '{domain.name}'"

    domain.issuing_ca = issuing_ca
    domain.save()

    context.domain = domain

@when('the admin fills in the domain details with {name} and issuing CA "{ca_name}"')
def step_fill_domain_details(context: runner.Context, name: str, ca_name: str) -> None:  # noqa: ARG001
    """Fills in the domain creation form.

    Args:
        context (runner.Context): Behave context.
        name (str): The name of the domain.
        ca_name (str): The name of the issuing ca.
    """
    ca = IssuingCaModel.objects.get(unique_name=ca_name)

    assert ca.unique_name == ca_name, f"Issuing CA {ca_name} doesn't exist."
    # Prepare POST data
    context.domain_add_form_data = {
        'unique_name': name,
        'issuing_ca': ca.id,
        'auto_create_new_device': 'off',
        'allow_username_password_registration': 'on',
        'allow_idevid_registration': 'off',
        'domain_credential_auth': 'on',
        'domain_credential_auth_helptext': 'off',
        'username_password_auth': 'off',
        'allow_app_certs_without_domain': 'on'
    }

@then('the new domain with {name} and issuing CA "{ca_name}" should appear in the domain list')
def step_domain_list(context: runner.Context, name: str, ca_name: str) -> None:  # noqa: ARG001
    """Verifies that the new domain appears in the domain list.

    Args:
        context (runner.Context): Behave context.
        name (str): The name of the domain.
        ca_name (str): The name of the issuing ca.
    """
    soup = BeautifulSoup(context.response.content, "html.parser")

    # Find all <td> elements
    tds = soup.find_all("td")

    # Get their text content (unescaped and stripped)
    values = [td.get_text(strip=True) for td in tds]

    assert name in values, f"Domain {name} doesn't exist."
    assert ca_name in values, f"Issuing CA {ca_name} doesn't exist."


@when('the admin deletes the domain with the name {name}')
def step_delete_domain(context: runner.Context, name: str) -> None:  # noqa: ARG001
    """Deletes an domain by name.

    Args:
        context (runner.Context): Behave context.
        name (str): The name of the domain to be deleted.
    """

    context.response = context.authenticated_client.get(
        '/pki/domains/delete/'+ str(context.domain.id),
        follow=True,
        HTTP_X_REQUESTED_WITH="XMLHttpRequest"
    )

    assert context.response.status_code == 200, "Domain delete form submission failed"
    assert b"Confirm Domain Deletion" in context.response.content
    context.response = context.authenticated_client.post(f"/pki/domains/delete/{context.domain.id}/", data={}, follow=True)
    assert context.response.status_code == 200, "Domain deletion response"
    assert not DomainModel.objects.filter(id=context.domain.id).exists(), f"Deletion of the domain with name {name} failed."


@then('the domain {name} should no longer appear in the domain list')
def step_verify_domain_deletion(context: runner.Context, name: str) -> None:  # noqa: ARG001
    """Verifies that the domain no longer appears in the list.

    Args:
        context (runner.Context): Behave context.
        name (str): The name of the domain.
    """
    assert name not in context.response, f"Domain with name {name} still exist in the list"


@when('the admin attempts to view the details of a non-existent domain {non_existent_domain_id}')
def step_attempt_view_nonexistent(context: runner.Context, non_existent_domain_id: str) -> None:  # noqa: ARG001
    """Attempts to view details of a non-existent domain.

    Args:
        context (runner.Context): Behave context.
        non_existent_domain_id (str): The id a non-existent domain.
    """
    #Navigate (GET request) to the domain detailed page
    context.response = context.authenticated_client.get(f"/pki/domains/config/{non_existent_domain_id}")