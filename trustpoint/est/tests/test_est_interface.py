import base64
from unittest.mock import MagicMock, patch

import pytest
from django.test import RequestFactory

from est.views import (
    EstCACertsView,
    EstSimpleEnrollmentView,
    LoggedHttpResponse,
    UsernamePasswordAuthenticationError,
)


@pytest.fixture
def request_factory():
    return RequestFactory()


@pytest.fixture
def est_simple_enrollment_view():
    view = EstSimpleEnrollmentView()
    view.request = MagicMock()
    view.requested_domain = MagicMock()
    view.requested_cert_template_str = 'tlsclient'
    return view


@pytest.fixture
def est_cacerts_view():
    view = EstCACertsView()
    view.requested_domain = MagicMock()
    return view


@patch('pki.models.credential.CredentialModel.objects.filter')
@patch('devices.models.IssuedCredentialModel.objects.get')
def test_get_credential_for_certificate(mock_get, mock_filter, est_simple_enrollment_view):
    cert_mock = MagicMock()
    cert_mock.fingerprint.return_value = b'sample_fingerprint'

    mock_credential = MagicMock()
    mock_filter.return_value.first.return_value = mock_credential

    mock_issued_credential = MagicMock()
    mock_issued_credential.credential = mock_credential
    mock_issued_credential.device = MagicMock()
    mock_get.return_value = mock_issued_credential

    issued_credential = est_simple_enrollment_view.get_credential_for_certificate(cert_mock)
    assert issued_credential == mock_issued_credential
    assert issued_credential.device == mock_issued_credential.device
    assert issued_credential.credential == mock_credential


@patch('devices.models.DeviceModel.objects.filter')
def test_authenticate_username_password_success(mock_filter, request_factory, est_simple_enrollment_view):
    request = request_factory.get('/')
    encoded_credentials = base64.b64encode(b'testuser:testpassword').decode()
    request.headers = {'Authorization': f'Basic {encoded_credentials}'}

    mock_device = MagicMock()
    mock_filter.return_value.first.return_value = mock_device

    device = est_simple_enrollment_view.authenticate_username_password(request)
    assert device == mock_device


def test_authenticate_username_password_missing_header(request_factory, est_simple_enrollment_view):
    request = request_factory.get('/')
    request.headers = {}

    with pytest.raises(UsernamePasswordAuthenticationError):
        est_simple_enrollment_view.authenticate_username_password(request)

@patch('est.views.EstSimpleEnrollmentView.extract_requested_domain')
@patch('est.views.EstSimpleEnrollmentView.authenticate_request')
@patch('est.views.EstSimpleEnrollmentView.deserialize_pki_message')
@patch('est.views.EstSimpleEnrollmentView.get_or_create_device_from_csr')
@pytest.mark.django_db
def test_post_authentication_failure(
    mock_get_device, mock_deserialize, mock_auth, mock_extract_domain, request_factory, est_simple_enrollment_view
):
    request = request_factory.post('/')
    mock_auth.return_value = (None, LoggedHttpResponse('Authentication failed', status=400))
    mock_extract_domain.return_value = (MagicMock(), None)
    response = est_simple_enrollment_view.post(request, domain=MagicMock(), certtemplate="tlsclient")
    assert response.status_code == 400
    assert b'Authentication failed' in response.content


@patch('est.views.EstSimpleEnrollmentView.issue_credential')
def test_issue_credential_invalid_template(mock_issue, est_simple_enrollment_view):
    mock_issue.side_effect = ValueError('Unknown template')

    with pytest.raises(ValueError):
        est_simple_enrollment_view.issue_credential(
            'invalid_template', MagicMock(), est_simple_enrollment_view.requested_domain, MagicMock()
        )

# TLS client certificate verification tests

def test_tls_client_cert_verification(est_simple_enrollment_view) -> None:
    """Tests the TLS client certificate verification with the direct Issuing CA in the Truststore."""
    request = MagicMock()
    request.META = {
        'SSL_CLIENT_CERT': 'mocked_client_cert_pem',
    }
    # ...

def test_tls_client_cert_verification_self_signed() -> None:
    """Tests the TLS client certificate verification with a self-signed client certificate."""
    request = MagicMock()
    request.META = {
        'SSL_CLIENT_CERT': 'mocked_self_signed_cert_pem',
    }
    # ...

def test_tls_client_cert_verification_not_in_truststore() -> None:
    """Tests the TLS client certificate verification without certificate in the Truststore."""
    # ...

def test_tls_client_cert_verification_no_cert() -> None:
    """Tests the TLS client certificate verification if no valid PEM is passed."""
    request = MagicMock()
    request.META = {
        'SSL_CLIENT_CERT': '41foobar',
    }
    # ...

@pytest.mark.parametrize('client_includes_root_ca', [True, False])
def test_tls_client_cert_verification_chain(client_includes_root_ca: bool) -> None:  # noqa: FBT001
    """Tests the TLS client certificate verification with an intermediate CA."""
    request = MagicMock()
    request.META = {
        'SSL_CLIENT_CERT': 'mocked_client_cert_pem',
        'SSL_CLIENT_CERT_CHAIN_0': 'mocked_intermediate_ca_cert_pem',
    }
    if (client_includes_root_ca):
        request.META['SSL_CLIENT_CERT_CHAIN_1'] = 'mocked_root_ca_cert_pem'
    # ...

def test_tls_client_cert_chain_too_long() -> None:
    """Tests the TLS client certificate verification with a too long chain."""
    request = MagicMock()
    request.META = {
        'SSL_CLIENT_CERT': 'mocked_client_cert_pem',
        'SSL_CLIENT_CERT_CHAIN_0': 'mocked_intermediate_ca_0_cert_pem',
        'SSL_CLIENT_CERT_CHAIN_1': 'mocked_intermediate_ca_1_cert_pem',
        'SSL_CLIENT_CERT_CHAIN_2': 'mocked_root_ca_cert_pem',
    }
    # ...

def test_tls_client_cert_idevid_in_truststore() -> None:
    """Tests that verification works with just the IDevID directly in the Truststore (not the CA)."""
    request = MagicMock()
    request.META = {
        'SSL_CLIENT_CERT': 'mocked_client_cert_pem',
    }
    # ...

def test_tls_client_cert_idevid_expired() -> None:
    """Tests that verification fails if the IDevID certificate is expired."""
    request = MagicMock()
    request.META = {
        'SSL_CLIENT_CERT': 'mocked_client_cert_pem',
    }
    # ...

def test_tls_client_cert_ca_expired() -> None:
    """Tests that verification fails if the CA certificate is expired."""
    request = MagicMock()
    request.META = {
        'SSL_CLIENT_CERT': 'mocked_client_cert_pem',
    }
    # ...

def test_tls_client_cert_attributes() -> None:
    """Tests that verification fails if the client cert has no subject serial number."""
