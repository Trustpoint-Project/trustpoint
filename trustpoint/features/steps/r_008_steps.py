"""Python steps file for R_008."""

from behave import runner, then, when, given
from bs4 import BeautifulSoup
import os
from pki.forms import (
    IssuingCaAddFileImportPkcs12Form,
)
from django.core.files.uploadedfile import SimpleUploadedFile
from trustpoint_core.serializer import (
    CertificateCollectionSerializer,
    CertificateSerializer,
    CredentialSerializer,
    PrivateKeySerializer,
)
from cryptography import x509
from cryptography.hazmat.backends import default_backend



@given('the admin is on the "pki/issuing-cas" webpage')
def step_given_admin_on_ca_page(context: runner.Context) -> None:  # noqa: ARG001
    """The admin navigates to the pki/issuing-cas webpage.

    Args:
        context (runner.Context): Behave context.
    """
    context.response = context.authenticated_client.get("/pki/issuing-cas/")
    # Check that page loaded successfully
    assert context.response.status_code == 200, f"Failed to load issuing CA page"

@then('the system should display multiple options to add a new issuing CA')
def step_then_ca_page_show_options(context: runner.Context) -> None:  # noqa: ARG001
    """Verifies that Add new issuing CA page shows multiple options.

    Args:
        context (runner.Context): Behave context.
    """
    html = context.response.content
    assert b'/pki/issuing-cas/add/file-import/pkcs12' in html, \
        "Missing link for importing from PKCS#12 file"

    assert b'Import From PKCS#12 File' in html, \
        "Missing text for PKCS#12 import option"

    assert b'/pki/issuing-cas/add/file-import/separate-files' in html, \
        "Missing link for importing from separate files"

    assert b'Import From Separate Key and Certificate Files' in html, \
        "Missing text for separate file import option"

@when('the admin clicks on "import from PKCS12 file"')
def step_when_click_on_import_from_pkcs12(context: runner.Context) -> None:  # noqa: ARG001
    """The admin navigates to the /pki/issuing-cas/add/file-import/pkcs12 webpage.

    Args:
        context (runner.Context): Behave context.
    """
    context.response = context.authenticated_client.get("/pki/issuing-cas/add/file-import/pkcs12")
    # Check that page loaded successfully
    assert context.response.status_code == 200, f"Failed to load issuing Add new Issuing CA using pkcs#12 import"

@when('the admin clicks on "import from separate key and certificate files"')
def step_when_click_import_from_separate_file(context: runner.Context) -> None:  # noqa: ARG001
    """The admin navigates to the /pki/issuing-cas/add/file-import/ webpage.

    Args:
        context (runner.Context): Behave context.
    """
    context.response = context.authenticated_client.get("/pki/issuing-cas/add/file-import/separate-files")
    # Check that page loaded successfully
    assert context.response.status_code == 200, f"Failed to load issuing Add new Issuing CA using import from separate files"

@then('the system should display a form page where a file can be uploaded')
def step_then_load_form(context: runner.Context) -> None:  # noqa: ARG001
    """Verifies that a form is loaded.

    Args:
        context (runner.Context): Behave context.
    """
    soup = BeautifulSoup(context.response.content, 'html.parser')

    # Check for presence of <form>
    form = soup.find('form')
    assert form is not None, "No <form> element found in the response"

    # Check for the specific <input> inside the form
    input_element = soup.find('input', {
        'type': 'file',
        # 'name': 'pkcs12_file',
        # 'class': 'form-control',
        # 'id': 'id_pkcs12_file',
    })
    assert input_element is not None, "Expected <input> for PKCS#12 file not found inside the form"

@when('the admin uploads a valid PKCS12 issuing CA file')
def step_when_pkcs12_file_import(context: runner.Context) -> None:  # noqa: ARG001
    """The admin uploads valid pkcs12 file.

    Args:
        context (runner.Context): Behave context.
    """
    # Ensure the file path is absolute and exists
    pkcs12_file_path = os.path.abspath("../tests/data/issuing_cas/issuing_ca.p12")
    assert os.path.exists(pkcs12_file_path), f"File not found: {pkcs12_file_path}"
    context.pkcs12_file_path = pkcs12_file_path

@when('the admin uploads a duplicated PKCS12 issuing CA file')
def step_when_duplicate_pkcs12_file_import(context: runner.Context) -> None:  # noqa: ARG001
    """The admin uploads duplicate pkcs12 file.

    Args:
        context (runner.Context): Behave context.
    """
    # Ensure the file path is absolute and exists
    pkcs12_file_path = os.path.abspath("../tests/data/issuing_cas/issuing_ca.p12")
    assert os.path.exists(pkcs12_file_path), f"File not found: {pkcs12_file_path}"
    context.pkcs12_file_path = pkcs12_file_path

@when('the admin clicks the "Add new issuing CA" button')
def step_when_pkcs12_file_import(context: runner.Context) -> None:  # noqa: ARG001
    """The admin click the button to submit form.

    Args:
        context (runner.Context): Behave context.
    """
    if hasattr(context, "pkcs12_file_path"):
        with open(context.pkcs12_file_path, "rb") as f:
            data = {
                'unique_name': "test",
                'pkcs12_password': "testing321",
                'pkcs12_file': f
            }
            # Adjust the URL to match the form action for your backend
            context.response = context.authenticated_client.post(
                "/pki/issuing-cas/add/file-import/pkcs12",
                data=data,
                follow=True
            )
            assert context.response.status_code == 200, f"Failed to submit the form."
    else:
        with open(context.key_file_path, "rb") as key_file, open(context.cert_file_path, "rb") as cert_file:
            separate_file_form_data = {
                'unique_name': "test",
                'pkcs12_password': "",
                'private_key_file': key_file,
                'ca_certificate': cert_file
            }
            # Adjust the URL to match the form action for your backend
            context.response = context.authenticated_client.post(
                "/pki/issuing-cas/add/file-import/separate-files",
                data=separate_file_form_data,
                follow=True
            )
            assert context.response.status_code == 200, f"Failed to submit the form."

@then('the added issuing CA "{name}" "appears" in the list of available CAs')
def step_then_new_ca_available(context: runner.Context, name: str) -> None:  # noqa: ARG001
    """Verifies new issuing CA is available in the list.

    Args:
        context (runner.Context): Behave context.
    """
    context.response = context.authenticated_client.get("/pki/issuing-cas/")
    soup = BeautifulSoup(context.response.content, "html.parser")

    # Find all <td> elements
    tds = soup.find_all("td")

    # Get their text content (unescaped and stripped)
    values = [td.get_text(strip=True) for td in tds]

    assert name in values, f"Issuing CA with name {name} doesn't exist"

@given('the issuing ca with pkcs12 file exist')
def step_when_pkcs12_file_import(context: runner.Context) -> None:  # noqa: ARG001
    """The issuing ca exist.

    Args:
        context (runner.Context): Behave context.
    """
    pkcs12_file_path = os.path.abspath("../tests/data/issuing_cas/issuing_ca.p12")
    with open(pkcs12_file_path, "rb") as f:
        data = {
            'unique_name': "test",
            'pkcs12_password': "testing321",
            'pkcs12_file': f
        }
        # Adjust the URL to match the form action for your backend
        response = context.authenticated_client.post(
            "/pki/issuing-cas/add/file-import/pkcs12",
            data=data,
            follow=True
        )
        assert response.status_code == 200, f"Failed to submit the CA form."
        response = context.authenticated_client.get("/pki/issuing-cas/")
        soup = BeautifulSoup(response.content, "html.parser")

        # Find all <td> elements
        tds = soup.find_all("td")

        # Get their text content (unescaped and stripped)
        values = [td.get_text(strip=True) for td in tds]

        assert "test" in values, f"Issuing CA test doesn't exist"



@when('the admin uploads a broken PKCS12 issuing CA file')
def step_when_pkcs12_file_import(context: runner.Context) -> None:  # noqa: ARG001
    """The admin uploads valid pkcs12 file.

    Args:
        context (runner.Context): Behave context.
    """
    # Ensure the file path is absolute and exists
    pkcs12_file_path = os.path.abspath("../tests/data/issuing_cas/issuing_ca_broken.p12")
    assert os.path.exists(pkcs12_file_path), f"File not found: {pkcs12_file_path}"
    context.pkcs12_file_path = pkcs12_file_path

@then('the added issuing CA "{name}" "does not appear" in the list of available CAs')
def step_then_new_ca_not_available(context: runner.Context, name: str) -> None:  # noqa: ARG001
    """Verifies new issuing CA is not available in the list.

    Args:
        context (runner.Context): Behave context.
    """
    context.response = context.authenticated_client.get("/pki/issuing-cas/")
    soup = BeautifulSoup(context.response.content, "html.parser")

    # Find all <td> elements
    tds = soup.find_all("td")

    # Get their text content (unescaped and stripped)
    values = [td.get_text(strip=True) for td in tds]

    assert name not in values, f"Issuing CA test doesn't exist"

@when('the key file of type {key_type} is "{status}"')
@when('the key file of type "{key_type}" is "{status}"')
def step_when_key_file_import(context: runner.Context, key_type: str, status: str) -> None:  # noqa: ARG001
    """The admin uploads key file of type and with a status.

    Args:
        context (runner.Context): Behave context.
    """
    # Ensure the file path is absolute and exists
    file_path = os.path.abspath(f"../tests/data/issuing_cas/key0_{status}{key_type}")
    assert os.path.exists(file_path), f"Key file not found: {file_path}"
    context.key_file_path = file_path
    with open(context.key_file_path, "rb") as key_file:
        private_key_serializer = PrivateKeySerializer.from_bytes(key_file.read(), None)
        assert private_key_serializer is not None, "Private key file is not valid"

@when('the certificate file of type {cert_type} is "{status}"')
@when('the certificate file of type "{cert_type}" is "{status}"')
def step_when_cert_file_import(context: runner.Context, cert_type: str, status: str) -> None:  # noqa: ARG001
    """The admin uploads certificate file of type and with a status.

    Args:
        context (runner.Context): Behave context.
    """
    # Ensure the file path is absolute and exists
    file_path = os.path.abspath(f"../tests/data/issuing_cas/ee0_{status}{cert_type}")
    assert os.path.exists(file_path), f"Certificate file not found: {file_path}"
    context.cert_file_path = file_path

@when('the certificate file is "a CA certificate"')
def step_when_cert_file_ca(context: runner.Context) -> None:  # noqa: ARG001
    """Ensures that certificate file is a CA certificate.

    Args:
        context (runner.Context): Behave context.
    """
  
    with open(context.cert_file_path, "rb") as cert_file:
        certificate_serializer = CertificateSerializer.from_bytes(cert_file.read())
        is_ca = is_ca_cert(certificate_serializer._certificate)
        assert is_ca is not None, "Certificate file is not valid"

@when('the certificate file is "an end entity certificate"')
def step_when_cert_file_ca(context: runner.Context) -> None:  # noqa: ARG001
    """Ensures that certificate file is a CA certificate.

    Args:
        context (runner.Context): Behave context.
    """
    with open(context.cert_file_path, "rb") as cert_file:
        certificate_serializer = CertificateSerializer.from_bytes(cert_file.read())
        is_ca = is_ca_cert(certificate_serializer._certificate)
        assert not is_ca, "the certificate is not end-entity certificate"

@when('the certificate chain of type {cert_chain} is "{status}"')
@when('the certificate chain of type "{cert_chain}" is "{status}"')
def step_when_cert_chain_file_import(context: runner.Context, cert_chain: str, status: str) -> None:  # noqa: ARG001
    """The admin uploads certificate chain file of type and with a status.

    Args:
        context (runner.Context): Behave context.
    """
    # Ensure the file path is absolute and exists
    file_path = os.path.abspath(f"../tests/data/issuing_cas/ee0_{status}{cert_chain}")
    assert os.path.exists(file_path), f"File not found: {file_path}"
    context.cert_chain_path = file_path

def is_ca_cert(cert: any) -> bool:
    basic_constraints = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
    return basic_constraints.ca is True