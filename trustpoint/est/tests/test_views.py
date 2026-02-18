"""Comprehensive tests for EST views.py module."""

import base64
from unittest.mock import MagicMock, Mock, patch

import pytest
from django.test import RequestFactory
from pki.models.domain import DomainModel
from request.request_context import EstCertificateRequestContext

from est.views import (
    EstCACertsView,
    EstCsrAttrsView,
    EstRequestedDomainExtractorMixin,
    EstSimpleEnrollmentMixin,
    EstSimpleEnrollmentView,
    EstSimpleReEnrollmentView,
    LoggedHttpResponse,
    UsernamePasswordAuthenticationError,
)


@pytest.fixture
def request_factory():
    """Fixture providing Django RequestFactory."""
    return RequestFactory()


@pytest.fixture
def mock_domain():
    """Fixture providing a mock DomainModel."""
    domain = Mock(spec=DomainModel)
    domain.unique_name = 'test_domain'
    domain.issuing_ca = Mock()
    domain.issuing_ca.credential = Mock()
    return domain


# ============================================================================
# Tests for UsernamePasswordAuthenticationError
# ============================================================================


def test_username_password_authentication_error():
    """Test that UsernamePasswordAuthenticationError can be raised."""
    with pytest.raises(UsernamePasswordAuthenticationError):
        raise UsernamePasswordAuthenticationError('Authentication failed')


def test_username_password_authentication_error_message():
    """Test that UsernamePasswordAuthenticationError preserves error message."""
    error_msg = 'Invalid credentials'
    error = UsernamePasswordAuthenticationError(error_msg)
    assert str(error) == error_msg


# ============================================================================
# Tests for LoggedHttpResponse
# ============================================================================


def test_logged_http_response_success_status():
    """Test LoggedHttpResponse logs success for status < 400."""
    with patch.object(LoggedHttpResponse, 'logger') as mock_logger:
        response = LoggedHttpResponse(content='Success', status=200)
        assert response.status_code == 200
        assert response.content == b'Success'
        mock_logger.info.assert_called_once()
        assert 'SUCCESS' in str(mock_logger.info.call_args)


def test_logged_http_response_error_status():
    """Test LoggedHttpResponse logs error for status >= 400."""
    with patch.object(LoggedHttpResponse, 'logger') as mock_logger:
        response = LoggedHttpResponse(content='Error occurred', status=404)
        assert response.status_code == 404
        mock_logger.error.assert_called_once()
        assert 'ERROR' in str(mock_logger.error.call_args)


def test_logged_http_response_bytes_content():
    """Test LoggedHttpResponse handles bytes content."""
    with patch.object(LoggedHttpResponse, 'logger') as mock_logger:
        response = LoggedHttpResponse(content=b'Byte content', status=500)
        assert response.status_code == 500
        mock_logger.error.assert_called_once()


def test_logged_http_response_default_status():
    """Test LoggedHttpResponse with default status (200)."""
    response = LoggedHttpResponse(content='Default status')
    assert response.status_code == 200


def test_logged_http_response_threshold_400():
    """Test LoggedHttpResponse threshold at exactly 400."""
    with patch.object(LoggedHttpResponse, 'logger') as mock_logger:
        response = LoggedHttpResponse(content='Threshold', status=400)
        assert response.status_code == 400
        mock_logger.error.assert_called_once()


def test_logged_http_response_threshold_399():
    """Test LoggedHttpResponse threshold at 399 (just below)."""
    with patch.object(LoggedHttpResponse, 'logger') as mock_logger:
        response = LoggedHttpResponse(content='Below threshold', status=399)
        assert response.status_code == 399
        mock_logger.info.assert_called_once()


# ============================================================================
# Tests for EstRequestedDomainExtractorMixin
# ============================================================================


def test_extract_requested_domain_success(mock_domain):
    """Test successful domain extraction."""
    mixin = EstRequestedDomainExtractorMixin()

    with patch.object(DomainModel.objects, 'get', return_value=mock_domain):
        domain, response = mixin.extract_requested_domain('test_domain')

        assert domain == mock_domain
        assert response is None


def test_extract_requested_domain_not_found():
    """Test domain extraction when domain does not exist."""
    mixin = EstRequestedDomainExtractorMixin()

    with patch.object(DomainModel.objects, 'get', side_effect=DomainModel.DoesNotExist):
        domain, response = mixin.extract_requested_domain('nonexistent_domain')

        assert domain is None
        assert isinstance(response, LoggedHttpResponse)
        assert response.status_code == 404
        assert b'Domain does not exist' in response.content


# ============================================================================
# Tests for EstSimpleEnrollmentMixin
# ============================================================================


def test_est_simple_enrollment_mixin_event():
    """Test that EstSimpleEnrollmentMixin has correct EVENT attribute."""
    from workflows.events import Events

    assert EstSimpleEnrollmentMixin.EVENT == Events.est_simpleenroll


@patch('est.views.EstErrorMessageResponder')
@patch('est.views.EstMessageResponder')
@patch('est.views.OperationProcessor')
@patch('est.views.WorkflowHandler')
@patch('est.views.EstAuthorization')
@patch('est.views.EstAuthentication')
@patch('est.views.EstMessageParser')
@patch('est.views.EstHttpRequestValidator')
@patch('est.views.EstCertificateRequestContext')
def test_process_enrollment_success(
    mock_request_context,
    mock_validator,
    mock_parser,
    mock_auth,
    mock_authz,
    mock_workflow,
    mock_processor,
    mock_responder,
    mock_error_responder,
    request_factory,
):
    """Test successful enrollment processing."""
    from django.http import HttpResponse

    # Setup mocks
    mock_ctx = Mock(spec=EstCertificateRequestContext)
    mock_ctx.http_response_content = b'Certificate issued'
    mock_ctx.http_response_status = 200
    mock_ctx.http_response_content_type = 'application/pkcs7-mime'
    mock_request_context.return_value = mock_ctx

    # Configure parser mock to return the context
    mock_parser.return_value.parse.return_value = mock_ctx

    # Mock to_http_response to return actual HttpResponse
    mock_ctx.to_http_response.return_value = HttpResponse(
        content=mock_ctx.http_response_content,
        status=mock_ctx.http_response_status,
        content_type=mock_ctx.http_response_content_type,
    )

    # Create view and request
    mixin = EstSimpleEnrollmentMixin()
    request = request_factory.post('/est/simpleenroll', data=b'CSR_DATA', content_type='application/pkcs10')

    # Execute
    response = mixin.process_enrollment(request, 'test_domain', 'tls_client')

    # Verify
    assert response.status_code == 200
    assert response.content == b'Certificate issued'
    mock_validator.return_value.validate.assert_called_once_with(mock_ctx)
    mock_parser.return_value.parse.assert_called_once_with(mock_ctx)
    mock_auth.return_value.authenticate.assert_called_once_with(mock_ctx)
    mock_authz.return_value.authorize.assert_called_once_with(mock_ctx)
    mock_workflow.return_value.handle.assert_called_once_with(mock_ctx)
    mock_processor.return_value.process_operation.assert_called_once_with(mock_ctx)
    mock_responder.build_response.assert_called_once_with(mock_ctx)
    mock_error_responder.build_response.assert_not_called()


@patch('est.views.EstCertificateRequestContext')
def test_process_enrollment_request_context_failure(mock_request_context, request_factory):
    """Test enrollment processing when EstCertificateRequestContext initialization fails."""
    mock_request_context.side_effect = Exception('Context creation failed')

    mixin = EstSimpleEnrollmentMixin()
    request = request_factory.post('/est/simpleenroll', data=b'CSR_DATA', content_type='application/pkcs10')

    response = mixin.process_enrollment(request, 'test_domain', 'tls_client')

    assert response.status_code == 500
    assert b'Failed to set up EST request context' in response.content


@patch('est.views.EstErrorMessageResponder')
@patch('est.views.EstHttpRequestValidator')
@patch('est.views.EstCertificateRequestContext')
def test_process_enrollment_validation_failure(
    mock_request_context, mock_validator, mock_error_responder, request_factory
):
    """Test enrollment processing when validation fails."""
    from django.http import HttpResponse

    mock_ctx = Mock(spec=EstCertificateRequestContext)
    mock_ctx.http_response_content = b'Validation error'
    mock_ctx.http_response_status = 400
    mock_ctx.http_response_content_type = 'text/plain'
    mock_request_context.return_value = mock_ctx

    # Mock to_http_response to return actual HttpResponse
    mock_ctx.to_http_response.return_value = HttpResponse(
        content=mock_ctx.http_response_content,
        status=mock_ctx.http_response_status,
        content_type=mock_ctx.http_response_content_type,
    )

    mock_validator.return_value.validate.side_effect = Exception('Validation failed')

    mixin = EstSimpleEnrollmentMixin()
    request = request_factory.post('/est/simpleenroll', data=b'CSR_DATA', content_type='application/pkcs10')

    response = mixin.process_enrollment(request, 'test_domain', 'tls_client')

    assert response.status_code == 400
    mock_error_responder.build_response.assert_called_once_with(mock_ctx)


# ============================================================================
# Tests for EstSimpleEnrollmentView
# ============================================================================


def test_est_simple_enrollment_view_csrf_exempt():
    """Test that EstSimpleEnrollmentView has CSRF exemption."""
    view = EstSimpleEnrollmentView()
    # Check that the view class has csrf_exempt decorator applied
    assert hasattr(EstSimpleEnrollmentView, 'dispatch')


@patch.object(EstSimpleEnrollmentMixin, 'process_enrollment')
def test_est_simple_enrollment_view_post(mock_process, request_factory):
    """Test POST request to EstSimpleEnrollmentView."""
    mock_response = LoggedHttpResponse('Success', status=200)
    mock_process.return_value = mock_response

    view = EstSimpleEnrollmentView.as_view()
    request = request_factory.post(
        '/est/simpleenroll/test_domain/tls_client', data=b'CSR', content_type='application/pkcs10'
    )
    
    response = view(request, domain='test_domain', cert_profile='tls_client')
    
    assert response.status_code == 200
    mock_process.assert_called_once()
    call_args = mock_process.call_args
    assert call_args[0][1] == 'test_domain'
    assert call_args[0][2] == 'tls_client'


# ============================================================================
# Tests for EstSimpleReEnrollmentView
# ============================================================================


def test_est_simple_reenrollment_view_event():
    """Test that EstSimpleReEnrollmentView has correct EVENT attribute."""
    from workflows.events import Events

    assert EstSimpleReEnrollmentView.EVENT == Events.est_simplereenroll


def test_est_simple_reenrollment_view_csrf_exempt():
    """Test that EstSimpleReEnrollmentView has CSRF exemption."""
    view = EstSimpleReEnrollmentView()
    assert hasattr(EstSimpleReEnrollmentView, 'dispatch')


@patch('est.views.EstErrorMessageResponder')
@patch('est.views.EstMessageResponder')
@patch('est.views.OperationProcessor')
@patch('est.views.WorkflowHandler')
@patch('est.views.EstAuthorization')
@patch('est.views.EstAuthentication')
@patch('est.views.EstMessageParser')
@patch('est.views.EstHttpRequestValidator')
@patch('est.views.EstCertificateRequestContext')
def test_est_simple_reenrollment_view_post_success(
    mock_request_context,
    mock_validator,
    mock_parser,
    mock_auth,
    mock_authz,
    mock_workflow,
    mock_processor,
    mock_responder,
    mock_error_responder,
    request_factory,
):
    """Test successful reenrollment via POST."""
    from django.http import HttpResponse

    # Setup mocks
    mock_ctx = MagicMock(spec=EstCertificateRequestContext)
    mock_ctx.http_response_content = b'Certificate renewed'
    mock_ctx.http_response_status = 200
    mock_ctx.http_response_content_type = 'application/pkcs7-mime'
    mock_request_context.return_value = mock_ctx

    # Configure parser mock to return the context
    mock_parser.return_value.parse.return_value = mock_ctx

    # Mock to_http_response to return actual HttpResponse
    mock_ctx.to_http_response.return_value = HttpResponse(
        content=mock_ctx.http_response_content,
        status=mock_ctx.http_response_status,
        content_type=mock_ctx.http_response_content_type,
    )

    # Create view and request
    view = EstSimpleReEnrollmentView.as_view()
    request = request_factory.post(
        '/est/simplereenroll/test_domain/tls_client', data=b'CSR_DATA', content_type='application/pkcs10'
    )

    # Execute
    response = view(request, domain='test_domain', cert_profile='tls_client')
    
    # Verify
    assert response.status_code == 200
    assert response.content == b'Certificate renewed'
    mock_validator.return_value.validate.assert_called_once_with(mock_ctx)
    mock_parser.return_value.parse.assert_called_once_with(mock_ctx)
    mock_auth.return_value.authenticate.assert_called_once_with(mock_ctx)
    mock_authz.return_value.authorize.assert_called_once()
    assert mock_authz.call_args[1]['allowed_operations'] == ['simplereenroll']
    mock_workflow.return_value.handle.assert_called_once_with(mock_ctx)
    mock_processor.return_value.process_operation.assert_called_once_with(mock_ctx)
    mock_responder.build_response.assert_called_once_with(mock_ctx)
    mock_error_responder.build_response.assert_not_called()


@patch('est.views.EstCertificateRequestContext')
def test_est_simple_reenrollment_view_post_context_failure(mock_request_context, request_factory):
    """Test reenrollment when EstCertificateRequestContext initialization fails."""
    mock_request_context.side_effect = Exception('Context creation failed')

    view = EstSimpleReEnrollmentView.as_view()
    request = request_factory.post(
        '/est/simplereenroll/test_domain/tls_client', data=b'CSR_DATA', content_type='application/pkcs10'
    )
    
    response = view(request, domain='test_domain', cert_profile='tls_client')
    
    assert response.status_code == 500
    assert b'Failed to set up request context' in response.content


@patch('est.views.EstErrorMessageResponder')
@patch('est.views.EstAuthentication')
@patch('est.views.EstHttpRequestValidator')
@patch('est.views.EstCertificateRequestContext')
def test_est_simple_reenrollment_view_post_authentication_failure(
    mock_request_context, mock_validator, mock_auth, mock_error_responder, request_factory
):
    """Test reenrollment when authentication fails."""
    from django.http import HttpResponse

    mock_ctx = Mock(spec=EstCertificateRequestContext)
    mock_ctx.http_response_content = b'Authentication error'
    mock_ctx.http_response_status = 401
    mock_ctx.http_response_content_type = 'text/plain'
    mock_request_context.return_value = mock_ctx

    # Mock to_http_response to return actual HttpResponse
    mock_ctx.to_http_response.return_value = HttpResponse(
        content=mock_ctx.http_response_content,
        status=mock_ctx.http_response_status,
        content_type=mock_ctx.http_response_content_type,
    )

    mock_auth.return_value.authenticate.side_effect = Exception('Auth failed')

    view = EstSimpleReEnrollmentView.as_view()
    request = request_factory.post(
        '/est/simplereenroll/test_domain/tls_client', data=b'CSR_DATA', content_type='application/pkcs10'
    )
    
    response = view(request, domain='test_domain', cert_profile='tls_client')
    
    assert response.status_code == 401
    mock_error_responder.build_response.assert_called_once_with(mock_ctx)


# ============================================================================
# Tests for EstCACertsView
# ============================================================================


def test_est_cacerts_view_csrf_exempt():
    """Test that EstCACertsView has CSRF exemption."""
    view = EstCACertsView()
    assert hasattr(EstCACertsView, 'dispatch')


@patch.object(EstRequestedDomainExtractorMixin, 'extract_requested_domain')
def test_est_cacerts_view_get_success(mock_extract_domain, request_factory, mock_domain):
    """Test successful GET request to EstCACertsView."""
    # Setup mock domain with issuing CA
    mock_credential_serializer = Mock()
    mock_chain_serializer = Mock()

    # Create mock PKCS7 DER data
    pkcs7_der = b'\x30\x82\x01\x23'  # Mock DER data
    mock_chain_serializer.as_pkcs7_der.return_value = pkcs7_der
    mock_credential_serializer.get_full_chain_as_serializer.return_value = mock_chain_serializer
    mock_domain.issuing_ca.credential.get_credential_serializer.return_value = mock_credential_serializer

    mock_extract_domain.return_value = (mock_domain, None)

    view = EstCACertsView.as_view()
    request = request_factory.get('/est/cacerts/test_domain')

    response = view(request, domain='test_domain')

    assert response.status_code == 200
    assert response['Content-Type'] == 'application/pkcs7-mime'
    assert response['Content-Transfer-Encoding'] == 'base64'
    assert 'Vary' not in response
    assert 'Content-Language' not in response

    # Verify base64 encoding
    expected_b64 = base64.b64encode(pkcs7_der).decode()
    assert expected_b64.replace('\n', '') in response.content.decode().replace('\n', '')


@patch.object(EstRequestedDomainExtractorMixin, 'extract_requested_domain')
def test_est_cacerts_view_get_domain_not_found(mock_extract_domain, request_factory):
    """Test GET request to EstCACertsView when domain doesn't exist."""
    error_response = LoggedHttpResponse('Domain does not exist', status=404)
    mock_extract_domain.return_value = (None, error_response)

    view = EstCACertsView.as_view()
    request = request_factory.get('/est/cacerts/nonexistent')

    response = view(request, domain='nonexistent')

    assert response.status_code == 404
    assert b'Domain does not exist' in response.content


@patch.object(EstRequestedDomainExtractorMixin, 'extract_requested_domain')
def test_est_cacerts_view_get_no_issuing_ca(mock_extract_domain, request_factory, mock_domain):
    """Test GET request to EstCACertsView when domain has no issuing CA."""
    mock_domain.issuing_ca = None
    mock_extract_domain.return_value = (mock_domain, None)

    view = EstCACertsView.as_view()
    request = request_factory.get('/est/cacerts/test_domain')

    response = view(request, domain='test_domain')

    assert response.status_code == 500
    assert b'no issuing CA configured' in response.content


@patch.object(EstRequestedDomainExtractorMixin, 'extract_requested_domain')
def test_est_cacerts_view_get_exception(mock_extract_domain, request_factory):
    """Test GET request to EstCACertsView when exception occurs."""
    mock_extract_domain.side_effect = Exception('Unexpected error')

    view = EstCACertsView.as_view()
    request = request_factory.get('/est/cacerts/test_domain')

    response = view(request, domain='test_domain')

    assert response.status_code == 500
    assert b'Error retrieving CA certificates' in response.content


@patch.object(EstRequestedDomainExtractorMixin, 'extract_requested_domain')
def test_est_cacerts_view_get_base64_line_wrapping(mock_extract_domain, request_factory, mock_domain):
    """Test that EstCACertsView properly wraps base64 output at 64 characters."""
    # Setup mock with long certificate data
    mock_credential_serializer = Mock()
    mock_chain_serializer = Mock()

    # Create long mock data to ensure line wrapping
    long_data = b'\x30' * 100  # 100 bytes will produce >64 char base64
    mock_chain_serializer.as_pkcs7_der.return_value = long_data
    mock_credential_serializer.get_full_chain_as_serializer.return_value = mock_chain_serializer
    mock_domain.issuing_ca.credential.get_credential_serializer.return_value = mock_credential_serializer

    mock_extract_domain.return_value = (mock_domain, None)

    view = EstCACertsView.as_view()
    request = request_factory.get('/est/cacerts/test_domain')

    response = view(request, domain='test_domain')

    assert response.status_code == 200

    # Check that lines are wrapped
    content = response.content.decode()
    lines = content.split('\n')

    # All lines except the last should be exactly 64 characters
    for line in lines[:-1]:
        assert len(line) == 64, f'Line length {len(line)} != 64'


@patch.object(EstRequestedDomainExtractorMixin, 'extract_requested_domain')
def test_est_cacerts_view_get_none_response_fallback(mock_extract_domain, request_factory, mock_domain):
    """Test EstCACertsView fallback when http_response is None after processing."""
    # This is a defensive test for the 'if not http_response' check at the end
    mock_domain.issuing_ca = None  # This should trigger error response
    mock_extract_domain.return_value = (mock_domain, None)

    view = EstCACertsView.as_view()
    request = request_factory.get('/est/cacerts/test_domain')

    response = view(request, domain='test_domain')

    # Should get error about missing CA, not the fallback
    assert response.status_code == 500


def test_est_cacerts_view_get_headers_removed(request_factory, mock_domain):
    """Test that Vary and Content-Language headers are removed from response."""
    # Setup mock domain with issuing CA
    mock_credential_serializer = Mock()
    mock_chain_serializer = Mock()

    pkcs7_der = b'\x30\x82\x01\x23'
    mock_chain_serializer.as_pkcs7_der.return_value = pkcs7_der
    mock_credential_serializer.get_full_chain_as_serializer.return_value = mock_chain_serializer
    mock_domain.issuing_ca.credential.get_credential_serializer.return_value = mock_credential_serializer

    # Patch to add headers to LoggedHttpResponse
    with patch.object(DomainModel.objects, 'get', return_value=mock_domain):
        with patch('est.views.LoggedHttpResponse') as MockResponse:
            # Create a response with Vary and Content-Language headers
            mock_response_instance = Mock()
            mock_response_instance.__contains__ = lambda self, key: key in ['Vary', 'Content-Language']
            mock_response_instance.__delitem__ = Mock()
            MockResponse.return_value = mock_response_instance

            view = EstCACertsView.as_view()
            request = request_factory.get('/est/cacerts/test_domain')

            response = view(request, domain='test_domain')

            # Verify delete was called for both headers
            assert mock_response_instance.__delitem__.call_count >= 2


# ============================================================================
# Tests for EstCsrAttrsView
# ============================================================================


def test_est_csrattrs_view_csrf_exempt():
    """Test that EstCsrAttrsView has CSRF exemption."""
    view = EstCsrAttrsView()
    assert hasattr(EstCsrAttrsView, 'dispatch')


def test_est_csrattrs_view_get(request_factory):
    """Test GET request to EstCsrAttrsView returns 404."""
    view = EstCsrAttrsView.as_view()
    request = request_factory.get('/est/csrattrs')

    response = view(request)

    assert response.status_code == 404
    assert b'csrattrs/ is not supported' in response.content


def test_est_csrattrs_view_get_with_domain(request_factory):
    """Test GET request to EstCsrAttrsView with domain parameter."""
    view = EstCsrAttrsView.as_view()
    request = request_factory.get('/est/csrattrs/test_domain')

    response = view(request, domain='test_domain')

    assert response.status_code == 404
    assert b'csrattrs/ is not supported' in response.content
