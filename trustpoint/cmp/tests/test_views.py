"""Tests for CMP views."""

from __future__ import annotations

from unittest.mock import MagicMock, Mock, patch

import pytest
from django.test import RequestFactory

from cmp.views import CmpCertificationRequestView, CmpInitializationRequestView


@pytest.fixture
def request_factory():
    """Provide a Django RequestFactory."""
    return RequestFactory()


@pytest.fixture
def mock_request_context():
    """Mock RequestContext."""
    ctx = Mock()
    ctx.http_response_content = b'test response'
    ctx.http_response_status = 200
    ctx.http_response_content_type = 'application/pkixcmp'
    return ctx


class TestCmpInitializationRequestView:
    """Tests for CmpInitializationRequestView."""

    def test_http_method_names(self):
        """Test that only POST method is allowed."""
        view = CmpInitializationRequestView()
        assert view.http_method_names == ('post',)

    def test_csrf_exempt_decorator(self):
        """Test that CSRF exemption is applied to the view."""
        # Check if the view has the csrf_exempt decorator
        view = CmpInitializationRequestView.as_view()
        assert hasattr(view, 'csrf_exempt')
        assert view.csrf_exempt is True

    @patch('cmp.views.CmpMessageResponder')
    @patch('cmp.views.CertificateIssueProcessor')
    @patch('cmp.views.ProfileValidator')
    @patch('cmp.views.CmpAuthorization')
    @patch('cmp.views.CmpAuthentication')
    @patch('cmp.views.CmpMessageParser')
    @patch('cmp.views.CmpHttpRequestValidator')
    @patch('cmp.views.RequestContext')
    def test_post_initialization_with_domain_only(
        self,
        mock_context_cls,
        mock_validator_cls,
        mock_parser_cls,
        mock_auth_cls,
        mock_authz_cls,
        mock_profile_validator_cls,
        mock_processor_cls,
        mock_responder_cls,
        request_factory,
        mock_request_context,
    ):
        """Test POST request to initialization endpoint with domain name only."""
        mock_context_cls.return_value = mock_request_context
        
        request = request_factory.post('/cmp/initialization/test_domain')
        view = CmpInitializationRequestView()
        
        response = view.post(request, domain_name='test_domain')
        
        # Verify RequestContext was created with correct parameters
        mock_context_cls.assert_called_once()
        call_kwargs = mock_context_cls.call_args[1]
        assert call_kwargs['domain_str'] == 'test_domain'
        assert call_kwargs['protocol'] == 'cmp'
        assert call_kwargs['operation'] == 'initialization'
        assert call_kwargs['cert_profile_str'] == 'domain_credential'
        
        # Verify all processors were called
        mock_validator_cls.return_value.validate.assert_called_once()
        mock_parser_cls.return_value.parse.assert_called_once()
        mock_auth_cls.return_value.authenticate.assert_called_once()
        mock_authz_cls.return_value.authorize.assert_called_once()
        mock_profile_validator_cls.validate.assert_called_once()
        mock_processor_cls.return_value.process_operation.assert_called_once()
        mock_responder_cls.build_response.assert_called_once()
        
        # Verify response
        assert response.status_code == 200
        assert response.content == b'test response'
        assert response['Content-Type'] == 'application/pkixcmp'

    @patch('cmp.views.CmpMessageResponder')
    @patch('cmp.views.CertificateIssueProcessor')
    @patch('cmp.views.ProfileValidator')
    @patch('cmp.views.CmpAuthorization')
    @patch('cmp.views.CmpAuthentication')
    @patch('cmp.views.CmpMessageParser')
    @patch('cmp.views.CmpHttpRequestValidator')
    @patch('cmp.views.RequestContext')
    def test_post_initialization_with_certificate_profile(
        self,
        mock_context_cls,
        mock_validator_cls,
        mock_parser_cls,
        mock_auth_cls,
        mock_authz_cls,
        mock_profile_validator_cls,
        mock_processor_cls,
        mock_responder_cls,
        request_factory,
        mock_request_context,
    ):
        """Test POST request to initialization endpoint with certificate profile."""
        mock_context_cls.return_value = mock_request_context
        
        request = request_factory.post('/cmp/p/test_domain/tls_client/initialization')
        view = CmpInitializationRequestView()
        
        response = view.post(request, domain_name='test_domain', certificate_profile='tls_client')
        
        # Verify RequestContext was created with correct profile
        call_kwargs = mock_context_cls.call_args[1]
        assert call_kwargs['cert_profile_str'] == 'tls_client'
        
        # Verify response
        assert response.status_code == 200

    @patch('cmp.views.CmpMessageResponder')
    @patch('cmp.views.CertificateIssueProcessor')
    @patch('cmp.views.ProfileValidator')
    @patch('cmp.views.CmpAuthorization')
    @patch('cmp.views.CmpAuthentication')
    @patch('cmp.views.CmpMessageParser')
    @patch('cmp.views.CmpHttpRequestValidator')
    @patch('cmp.views.RequestContext')
    def test_post_authorization_with_correct_operations(
        self,
        mock_context_cls,
        mock_validator_cls,
        mock_parser_cls,
        mock_auth_cls,
        mock_authz_cls,
        mock_profile_validator_cls,
        mock_processor_cls,
        mock_responder_cls,
        request_factory,
        mock_request_context,
    ):
        """Test that authorization is called with correct operations for initialization."""
        mock_context_cls.return_value = mock_request_context
        
        request = request_factory.post('/cmp/initialization/test_domain')
        view = CmpInitializationRequestView()
        
        view.post(request, domain_name='test_domain')
        
        # Verify CmpAuthorization was initialized with correct operations
        mock_authz_cls.assert_called_once_with(['initialization', 'certification'])


class TestCmpCertificationRequestView:
    """Tests for CmpCertificationRequestView."""

    def test_http_method_names(self):
        """Test that only POST method is allowed."""
        view = CmpCertificationRequestView()
        assert view.http_method_names == ('post',)

    def test_csrf_exempt_decorator(self):
        """Test that CSRF exemption is applied to the view."""
        view = CmpCertificationRequestView.as_view()
        assert hasattr(view, 'csrf_exempt')
        assert view.csrf_exempt is True

    @patch('cmp.views.CmpMessageResponder')
    @patch('cmp.views.CertificateIssueProcessor')
    @patch('cmp.views.ProfileValidator')
    @patch('cmp.views.CmpAuthorization')
    @patch('cmp.views.CmpAuthentication')
    @patch('cmp.views.CmpMessageParser')
    @patch('cmp.views.CmpHttpRequestValidator')
    @patch('cmp.views.RequestContext')
    def test_post_certification_with_domain_only(
        self,
        mock_context_cls,
        mock_validator_cls,
        mock_parser_cls,
        mock_auth_cls,
        mock_authz_cls,
        mock_profile_validator_cls,
        mock_processor_cls,
        mock_responder_cls,
        request_factory,
        mock_request_context,
    ):
        """Test POST request to certification endpoint with domain name only."""
        mock_context_cls.return_value = mock_request_context
        
        request = request_factory.post('/cmp/p/test_domain/certification')
        view = CmpCertificationRequestView()
        
        response = view.post(request, domain_name='test_domain')
        
        # Verify RequestContext was created with correct parameters
        mock_context_cls.assert_called_once()
        call_kwargs = mock_context_cls.call_args[1]
        assert call_kwargs['domain_str'] == 'test_domain'
        assert call_kwargs['protocol'] == 'cmp'
        assert call_kwargs['operation'] == 'certification'
        assert call_kwargs['cert_profile_str'] == 'tls_client'  # Default for certification
        
        # Verify all processors were called
        mock_validator_cls.return_value.validate.assert_called_once()
        mock_parser_cls.return_value.parse.assert_called_once()
        mock_auth_cls.return_value.authenticate.assert_called_once()
        mock_authz_cls.return_value.authorize.assert_called_once()
        mock_profile_validator_cls.validate.assert_called_once()
        mock_processor_cls.return_value.process_operation.assert_called_once()
        mock_responder_cls.build_response.assert_called_once()
        
        # Verify response
        assert response.status_code == 200
        assert response.content == b'test response'
        assert response['Content-Type'] == 'application/pkixcmp'

    @patch('cmp.views.CmpMessageResponder')
    @patch('cmp.views.CertificateIssueProcessor')
    @patch('cmp.views.ProfileValidator')
    @patch('cmp.views.CmpAuthorization')
    @patch('cmp.views.CmpAuthentication')
    @patch('cmp.views.CmpMessageParser')
    @patch('cmp.views.CmpHttpRequestValidator')
    @patch('cmp.views.RequestContext')
    def test_post_certification_with_certificate_profile(
        self,
        mock_context_cls,
        mock_validator_cls,
        mock_parser_cls,
        mock_auth_cls,
        mock_authz_cls,
        mock_profile_validator_cls,
        mock_processor_cls,
        mock_responder_cls,
        request_factory,
        mock_request_context,
    ):
        """Test POST request to certification endpoint with certificate profile."""
        mock_context_cls.return_value = mock_request_context
        
        request = request_factory.post('/cmp/p/test_domain/tls_server/certification')
        view = CmpCertificationRequestView()
        
        response = view.post(request, domain_name='test_domain', certificate_profile='tls_server')
        
        # Verify RequestContext was created with correct profile
        call_kwargs = mock_context_cls.call_args[1]
        assert call_kwargs['cert_profile_str'] == 'tls_server'
        
        # Verify response
        assert response.status_code == 200

    @patch('cmp.views.CmpMessageResponder')
    @patch('cmp.views.CertificateIssueProcessor')
    @patch('cmp.views.ProfileValidator')
    @patch('cmp.views.CmpAuthorization')
    @patch('cmp.views.CmpAuthentication')
    @patch('cmp.views.CmpMessageParser')
    @patch('cmp.views.CmpHttpRequestValidator')
    @patch('cmp.views.RequestContext')
    def test_post_authorization_with_certification_operation(
        self,
        mock_context_cls,
        mock_validator_cls,
        mock_parser_cls,
        mock_auth_cls,
        mock_authz_cls,
        mock_profile_validator_cls,
        mock_processor_cls,
        mock_responder_cls,
        request_factory,
        mock_request_context,
    ):
        """Test that authorization is called with correct operations for certification."""
        mock_context_cls.return_value = mock_request_context
        
        request = request_factory.post('/cmp/p/test_domain/certification')
        view = CmpCertificationRequestView()
        
        view.post(request, domain_name='test_domain')
        
        # Verify CmpAuthorization was initialized with only certification operation
        mock_authz_cls.assert_called_once_with(['certification'])
