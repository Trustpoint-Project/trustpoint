"""Tests for CMP views."""

from __future__ import annotations

from unittest.mock import MagicMock, Mock, patch

from django.http import Http404
import pytest
from django.test import RequestFactory
from django.urls import resolve

from cmp.views import CmpRequestView


@pytest.fixture
def request_factory():
    """Provide a Django RequestFactory."""
    return RequestFactory()


@pytest.fixture
def mock_request_context():
    """Mock CmpCertificateRequestContext."""
    from django.http import HttpResponse
    
    ctx = Mock()
    ctx.http_response_content = b'test response'
    ctx.http_response_status = 200
    ctx.http_response_content_type = 'application/pkixcmp'
    
    # Mock to_http_response to return actual HttpResponse
    ctx.to_http_response.return_value = HttpResponse(
        content=ctx.http_response_content,
        status=ctx.http_response_status,
        content_type=ctx.http_response_content_type
    )
    
    return ctx


class TestCmpInitializationRequestView:
    """Tests for CmpInitializationRequestView."""

    def test_http_method_names(self):
        """Test that only POST method is allowed."""
        view = CmpRequestView()
        assert view.http_method_names == ('post',)

    def test_csrf_exempt_decorator(self):
        """Test that CSRF exemption is applied to the view."""
        # Check if the view has the csrf_exempt decorator
        view = CmpRequestView.as_view()
        assert hasattr(view, 'csrf_exempt')
        assert view.csrf_exempt is True

    @patch('cmp.views.CmpMessageResponder')
    @patch('cmp.views.CertificateIssueProcessor')
    @patch('cmp.views.ProfileValidator')
    @patch('cmp.views.CmpAuthorization')
    @patch('cmp.views.CmpAuthentication')
    @patch('cmp.views.CmpMessageParser')
    @patch('cmp.views.CmpHttpRequestValidator')
    @patch('cmp.views.CmpCertificateRequestContext')
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
        
        # Configure parser mock to return the context
        mock_parser_cls.return_value.parse.return_value = mock_request_context
        
        request = request_factory.post('/cmp/initialization/test_domain')
        view = CmpRequestView()
        
        response = view.post(request, domain='test_domain')
        
        # Verify CmpCertificateRequestContext was created with correct parameters
        mock_context_cls.assert_called_once()
        call_kwargs = mock_context_cls.call_args[1]
        assert call_kwargs['domain_str'] == 'test_domain'
        assert call_kwargs['protocol'] == 'cmp'
        assert call_kwargs['operation'] == None
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
    @patch('cmp.views.CmpCertificateRequestContext')
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
        
        # Configure parser mock to return the context
        mock_parser_cls.return_value.parse.return_value = mock_request_context
        
        request = request_factory.post('/cmp/p/test_domain/tls_client/initialization')
        view = CmpRequestView()
        
        response = view.post(request, domain='test_domain', cert_profile='tls_client')
        
        # Verify CmpCertificateRequestContext was created with correct profile
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
    @patch('cmp.views.CmpCertificateRequestContext')
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
        
        # Configure parser mock to return the context
        mock_parser_cls.return_value.parse.return_value = mock_request_context
        
        request = request_factory.post('/cmp/initialization/test_domain')
        view = CmpRequestView()
        
        view.post(request, domain='test_domain')
        
        # Verify CmpAuthorization was initialized with correct operations
        mock_authz_cls.assert_called_once_with(['initialization', 'certification'])


class TestCmpCertificationRequestView:
    """Tests for CmpCertificationRequestView."""

    @patch('cmp.views.CmpMessageResponder')
    @patch('cmp.views.CertificateIssueProcessor')
    @patch('cmp.views.ProfileValidator')
    @patch('cmp.views.CmpAuthorization')
    @patch('cmp.views.CmpAuthentication')
    @patch('cmp.views.CmpMessageParser')
    @patch('cmp.views.CmpHttpRequestValidator')
    @patch('cmp.views.CmpCertificateRequestContext')
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
        
        # Configure parser mock to return the context
        mock_parser_cls.return_value.parse.return_value = mock_request_context
        
        request = request_factory.post('/cmp/p/test_domain/certification')
        view = CmpRequestView()
        
        response = view.post(request, domain='test_domain')
        
        # Verify CmpCertificateRequestContext was created with correct parameters
        mock_context_cls.assert_called_once()
        call_kwargs = mock_context_cls.call_args[1]
        assert call_kwargs['domain_str'] == 'test_domain'
        assert call_kwargs['protocol'] == 'cmp'
        assert call_kwargs['operation'] == None
        assert call_kwargs['cert_profile_str'] == 'domain_credential'  # Default for certification should be 'tls_client'? # TODO: better automatic cert profile selection
        
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
    @patch('cmp.views.CmpCertificateRequestContext')
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
        
        # Configure parser mock to return the context
        mock_parser_cls.return_value.parse.return_value = mock_request_context
        
        request = request_factory.post('/cmp/p/test_domain/tls_server/certification')
        view = CmpRequestView()
        
        response = view.post(request, domain='test_domain', cert_profile='tls_server')
        
        # Verify CmpCertificateRequestContext was created with correct profile
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
    @patch('cmp.views.CmpCertificateRequestContext')
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
        
        # Configure parser mock to return the context
        mock_parser_cls.return_value.parse.return_value = mock_request_context
        
        request = request_factory.post('/cmp/p/test_domain/certification')
        view = CmpRequestView()
        
        view.post(request, domain='test_domain')
        
        mock_authz_cls.assert_called_once()


class TestCmpRequestViewPathParamExtraction:
    """Tests for path parameter extraction in CmpRequestView."""

    def test_extract_path_no_params(self, request_factory):
        """Test extraction with no path parameters."""

        url = resolve('/.well-known/cmp/')

        domain, profile, operation = CmpRequestView()._extract_path_params(url.kwargs)

        assert domain is None
        assert profile is None
        assert operation is None

    def test_extract_path_operation_only(self, request_factory):
        """Test extraction with only operation."""

        url = resolve('/.well-known/cmp/initialization')

        domain, profile, operation = CmpRequestView()._extract_path_params(url.kwargs)

        assert domain is None
        assert profile is None
        assert operation == 'initialization'

    def test_extract_path_domain_only(self, request_factory):
        """Test extraction with only domain name (with trailing slash)."""

        url = resolve('/.well-known/cmp/p/test_domain/')

        domain, profile, operation = CmpRequestView()._extract_path_params(url.kwargs)

        assert domain == 'test_domain'
        assert profile is None
        assert operation is None

    def test_extract_path_profile_only(self, request_factory):
        """Test extraction with only certificate profile."""

        url = resolve('/.well-known/cmp/p/~tls_client')

        domain, profile, operation = CmpRequestView()._extract_path_params(url.kwargs)

        assert domain is None
        assert profile == 'tls_client'
        assert operation is None

    def test_extract_path_profile_and_operation(self, request_factory):
        """Test extraction with only certificate profile."""

        url = resolve('/.well-known/cmp/p/~tls_client/initialization')

        domain, profile, operation = CmpRequestView()._extract_path_params(url.kwargs)

        assert domain is None
        assert profile == 'tls_client'
        assert operation == 'initialization'

    def test_extract_path_domain_and_profile(self, request_factory):
        """Test extraction with domain name and certificate profile."""

        url = resolve('/.well-known/cmp/p/test_domain/tls_client')
        domain, profile, operation = CmpRequestView()._extract_path_params(url.kwargs)

        assert domain == 'test_domain'
        assert profile == 'tls_client'
        assert operation is None

    def test_extract_path_domain_and_profile_td(self, request_factory):
        """Test extraction with domain name and certificate profile using ~ separator."""

        url = resolve('/.well-known/cmp/p/test_domain~tls_client/')
        domain, profile, operation = CmpRequestView()._extract_path_params(url.kwargs)

        assert domain == 'test_domain'
        assert profile == 'tls_client'
        assert operation is None

    def test_extract_path_domain_profile_td_operation(self, request_factory):
        """Test extraction with domain name, certificate profile using ~ separator, and operation."""

        url = resolve('/.well-known/cmp/p/test_domain~tls_client/initialization/')
        domain, profile, operation = CmpRequestView()._extract_path_params(url.kwargs)

        assert domain == 'test_domain'
        assert profile == 'tls_client'
        assert operation == 'initialization'

    def test_extract_path_domain_and_operation(self, request_factory):
        """Test extraction with domain name and operation."""

        url = resolve('/.well-known/cmp/p/test_domain/initialization/')
        domain, profile, operation = CmpRequestView()._extract_path_params(url.kwargs)

        assert domain == 'test_domain'
        assert profile is None
        assert operation == 'initialization'
    
    def test_extract_path_all(self, request_factory):
        """Test extraction with domain name, certificate profile, and operation."""

        url = resolve('/.well-known/cmp/p/test_domain/tls_client/initialization/')
        domain, profile, operation = CmpRequestView()._extract_path_params(url.kwargs)

        assert domain == 'test_domain'
        assert profile == 'tls_client'
        assert operation == 'initialization'

    def test_extract_path_empty_domain(self, request_factory):
        """Test extraction with empty domain segment."""

        url = resolve('/.well-known/cmp/p/_/tls_client/initialization/')
        domain, profile, operation = CmpRequestView()._extract_path_params(url.kwargs)

        assert domain is None
        assert profile == 'tls_client'
        assert operation == 'initialization'

    def test_extract_path_invalid_empty_profile_after_td(self, request_factory):
        """Test extraction with empty profile in domain segment."""
        url = resolve('/.well-known/cmp/p/test_domain~/initialization/')
        domain, profile, operation = CmpRequestView()._extract_path_params(url.kwargs)
        assert domain == 'test_domain'
        assert profile is None
        assert operation == 'initialization'

    def test_extract_path_invalid_profile_as_operation(self, request_factory):
        """Test extraction fails with (second) profile given instead of operation."""
        url = resolve('/.well-known/cmp/p/test_domain~tls_client/tls_server/')
        with pytest.raises(Http404):
            domain, profile, operation = CmpRequestView()._extract_path_params(url.kwargs)

    def test_extract_path_invalid_operation(self, request_factory):
        """Test extraction with invalid operation."""
        url = resolve('/.well-known/cmp/p/test_domain/tls_client/popcorn_gun!!!/')
        with pytest.raises(Http404):
            domain, profile, operation = CmpRequestView()._extract_path_params(url.kwargs)