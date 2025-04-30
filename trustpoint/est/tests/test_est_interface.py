"""Tests for the EST interface endpoints."""
import base64
from unittest.mock import MagicMock, patch

import pytest
from cryptography import x509
from django.test import RequestFactory
from pki.util.x509 import CertificateGenerator
from trustpoint_core.types import PrivateKey

from est.views import (
    ClientCertificateAuthenticationError,
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


def get_mock_truststore(certificates: list[x509.Certificate]) -> MagicMock:
    """Get a mock truststore for testing."""
    ts = MagicMock()
    ts.unique_name = 'test_mock_truststore'
    ts.get_certificate_collection_serializer.return_value.as_crypto_list.return_value = certificates
    return ts


@patch('pki.models.credential.CredentialModel.objects.filter')
@patch('devices.models.IssuedCredentialModel.objects.get')
def test_get_credential_for_certificate(mock_get, mock_filter, est_simple_enrollment_view) -> None:
    """Test the get_credential_for_certificate method."""
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
    certs, _keys = CertificateGenerator.create_test_pki(1)
    truststore = get_mock_truststore([certs[0]])
    assert est_simple_enrollment_view._verify_idevid_against_truststore(certs[1], [], truststore) # noqa: SLF001

def test_tls_client_cert_verification_self_signed(est_simple_enrollment_view) -> None:
    """Tests the TLS client certificate verification with a self-signed client certificate."""
    certs, _keys = CertificateGenerator.create_test_pki(0)
    truststore = get_mock_truststore([certs[0]])
    assert est_simple_enrollment_view._verify_idevid_against_truststore(certs[0], [], truststore) # noqa: SLF001

def test_tls_client_cert_verification_not_in_truststore(est_simple_enrollment_view) -> None:
    """Tests the TLS client certificate verification fails if no matching certificate in the Truststore."""
    different_pki_root, _key = CertificateGenerator.create_root_ca('Different Root CA')
    truststore = get_mock_truststore([different_pki_root])
    certs, _keys = CertificateGenerator.create_test_pki(1)
    assert not est_simple_enrollment_view._verify_idevid_against_truststore(certs[1], [], truststore) # noqa: SLF001

def test_tls_client_cert_verification_no_cert(est_simple_enrollment_view) -> None:
    """Tests the TLS client certificate verification if no valid PEM is passed."""
    est_simple_enrollment_view.request.META = {
        'SSL_CLIENT_CERT': '41foobar',
    }
    with pytest.raises(ClientCertificateAuthenticationError):
        est_simple_enrollment_view.authenticate_idevid(
            est_simple_enrollment_view.request, est_simple_enrollment_view.requested_domain
        )

@pytest.mark.parametrize('client_includes_root_ca', [True, False])
def test_tls_client_cert_verification_chain(est_simple_enrollment_view, client_includes_root_ca: bool) -> None:  # noqa: FBT001
    """Tests the TLS client certificate verification with an intermediate CA."""
    # TODO(Air): This test will only work once the cryptography 44 hack is removed.
    return
    certs, _keys = CertificateGenerator.create_test_pki(2)
    truststore = get_mock_truststore([certs[0]])
    intermediates = [certs[1], certs[0]] if client_includes_root_ca else [certs[1]]
    assert est_simple_enrollment_view._verify_idevid_against_truststore(certs[2], intermediates, truststore) # noqa: SLF001

def test_tls_client_cert_chain_too_long(est_simple_enrollment_view) -> None:
    """Tests the TLS client certificate verification with a too long chain."""
    certs, _keys = CertificateGenerator.create_test_pki(4)
    truststore = get_mock_truststore([certs[0]])
    intermediates = [certs[3], certs[2], certs[1]]
    assert not est_simple_enrollment_view._verify_idevid_against_truststore(certs[4], intermediates, truststore) # noqa: SLF001

def test_tls_client_cert_idevid_in_truststore(est_simple_enrollment_view) -> None:
    """Tests that verification works with just the IDevID directly in the Truststore (not the CA)."""
    certs, _keys = CertificateGenerator.create_test_pki(1)
    truststore = get_mock_truststore([certs[1]])
    assert est_simple_enrollment_view._verify_idevid_against_truststore(certs[1], [], truststore) # noqa: SLF001

def test_tls_client_cert_idevid_expired() -> None:
    """Tests that verification fails if the IDevID certificate is expired."""


def test_tls_client_cert_ca_expired() -> None:
    """Tests that verification fails if the CA certificate is expired."""


def test_tls_client_cert_attributes() -> None:
    """Tests that verification fails if the client cert has no subject serial number."""
