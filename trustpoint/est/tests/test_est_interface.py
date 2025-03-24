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
    mock_issued_credential.device = MagicMock()
    mock_get.return_value = mock_issued_credential

    credential, device = est_simple_enrollment_view.get_credential_for_certificate(cert_mock)
    assert credential == mock_credential
    assert device == mock_issued_credential.device


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


@patch('est.views.EstSimpleEnrollmentView.authenticate_request')
@patch('est.views.EstSimpleEnrollmentView.deserialize_pki_message')
@patch('est.views.EstSimpleEnrollmentView.get_or_create_device_from_csr')
def test_post_authentication_failure(
    mock_get_device, mock_deserialize, mock_auth, request_factory, est_simple_enrollment_view
):
    request = request_factory.post('/')
    mock_auth.return_value = (None, LoggedHttpResponse('Authentication failed', status=400))
    response = est_simple_enrollment_view.post(request)
    assert response.status_code == 400
    assert b'Authentication failed' in response.content


@patch('est.views.EstSimpleEnrollmentView.issue_credential')
def test_issue_credential_invalid_template(mock_issue, est_simple_enrollment_view):
    mock_issue.side_effect = ValueError('Unknown template')

    with pytest.raises(ValueError):
        est_simple_enrollment_view.issue_credential(
            'invalid_template', MagicMock(), est_simple_enrollment_view.requested_domain, MagicMock()
        )
