"""Tests for the EST interface endpoints."""

import base64
from unittest.mock import MagicMock, patch

import pytest
from cryptography import x509
from devices.models import IssuedCredentialModel
from django.test import RequestFactory
from pki.util.idevid import IDevIDAuthenticator
from pki.util.x509 import ClientCertificateAuthenticationError

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
    view.requested_cert_template_str = 'tls_client'
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
    ts.get_certificate_collection_serializer.return_value.as_crypto.return_value = certificates
    return ts


@patch('pki.models.credential.CredentialModel.objects.filter')
@patch('devices.models.IssuedCredentialModel.objects.get')
def test_get_credential_for_certificate(mock_get, mock_filter) -> None:
    """Test the get_credential_for_certificate method."""
    cert_mock = MagicMock()
    cert_mock.fingerprint.return_value = b'sample_fingerprint'

    mock_credential = MagicMock()
    mock_filter.return_value.first.return_value = mock_credential

    mock_issued_credential = MagicMock()
    mock_issued_credential.credential = mock_credential
    mock_issued_credential.device = MagicMock()
    mock_get.return_value = mock_issued_credential

    issued_credential = IssuedCredentialModel.get_credential_for_certificate(cert_mock)
    assert issued_credential == mock_issued_credential
    assert issued_credential.device == mock_issued_credential.device
    assert issued_credential.credential == mock_credential


def test_tls_client_cert_verification_no_cert(est_simple_enrollment_view) -> None:
    """Tests the TLS client certificate verification if no valid PEM is passed."""
    est_simple_enrollment_view.request.META = {
        'HTTP_SSL_CLIENT_CERT': '41foobar',
    }
    with pytest.raises(ClientCertificateAuthenticationError):
        IDevIDAuthenticator.authenticate_idevid(
            est_simple_enrollment_view.request, est_simple_enrollment_view.requested_domain
        )


def test_tls_client_cert_domain_credential_enrollment() -> None:
    """Tests that an issued credential can be enrolled via EST simpleenroll using an IDevID."""


def test_tls_client_cert_enrollment_twice() -> None:
    """Tests that the same domain credential cannot be enrolled twice via EST simpleenroll using an IDevID."""


def test_tls_client_cert_application_credential_enrollment() -> None:
    """Tests that an application credential cannot directly be enrolled via EST simpleenroll using an IDevID."""


def test_tls_reenrollment_valid() -> None:
    """Tests that an issued credential can be re-enrolled via EST simplereenroll."""


def test_tls_reenrollment_mismatched() -> None:
    """Tests that an issued credential cannot be re-enrolled if the TLS client cert does not match the issued cred.

    For this example, it is attempted to re-enroll a domain credential with an application credential.
    """
