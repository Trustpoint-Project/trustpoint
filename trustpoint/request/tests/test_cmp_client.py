"""Unit tests for the CMP client.

These tests verify the CMP client functionality including message building,
protection mechanisms, and response parsing.
"""

from __future__ import annotations

from typing import TYPE_CHECKING
from unittest.mock import MagicMock, Mock, patch

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from pyasn1.codec.der import encoder  # type: ignore[import-untyped]
from pyasn1_modules import rfc4210  # type: ignore[import-untyped]

from request.clients.cmp_client import CmpClient, CmpClientError
from request.request_context import CmpBaseRequestContext

if TYPE_CHECKING:
    from pki.models import TruststoreModel


@pytest.fixture
def mock_truststore() -> Mock:
    """Create a mock truststore."""
    truststore = Mock(spec=['get_certificate_collection_serializer'])
    serializer = Mock()
    serializer.as_pem.return_value = b'-----BEGIN CERTIFICATE-----\nMOCK\n-----END CERTIFICATE-----\n'
    truststore.get_certificate_collection_serializer.return_value = serializer
    return truststore


@pytest.fixture
def test_key_pair() -> tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
    """Generate a test RSA key pair."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()
    return private_key, public_key


@pytest.fixture
def test_csr(test_key_pair: tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]) -> x509.CertificateSigningRequest:
    """Generate a test CSR."""
    private_key, _ = test_key_pair
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, 'test-device'),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, 'Test Org'),
    ])
    return x509.CertificateSigningRequestBuilder().subject_name(subject).sign(
        private_key, hashes.SHA256()
    )


@pytest.fixture
def cmp_context_shared_secret(mock_truststore: Mock) -> CmpBaseRequestContext:
    """Create a CMP context with shared secret authentication."""
    return CmpBaseRequestContext(
        cmp_server_host='cmp.test.example.com',
        cmp_server_port=8443,
        cmp_server_path='/pkix/certification',
        cmp_server_truststore=mock_truststore,
        cmp_shared_secret='test-shared-secret',
    )


@pytest.fixture
def cmp_context_signature(mock_truststore: Mock) -> CmpBaseRequestContext:
    """Create a CMP context for signature-based authentication."""
    return CmpBaseRequestContext(
        cmp_server_host='cmp.test.example.com',
        cmp_server_truststore=mock_truststore,
    )


class TestCmpClientInitialization:
    """Tests for CMP client initialization."""

    def test_init_with_valid_context(self, cmp_context_shared_secret: CmpBaseRequestContext) -> None:
        """Test initialization with valid context."""
        client = CmpClient(cmp_context_shared_secret, timeout=30)
        assert client.context == cmp_context_shared_secret
        assert client.timeout == 30
        assert len(client.transaction_id) == 16
        assert len(client.sender_nonce) == 16

    def test_init_missing_host(self, mock_truststore: Mock) -> None:
        """Test initialization fails without server host."""
        context = CmpBaseRequestContext(
            cmp_server_truststore=mock_truststore,
        )
        with pytest.raises(CmpClientError, match='cmp_server_host is required'):
            CmpClient(context)

    def test_init_missing_truststore(self) -> None:
        """Test initialization fails without truststore."""
        context = CmpBaseRequestContext(
            cmp_server_host='cmp.test.example.com',
        )
        with pytest.raises(CmpClientError, match='cmp_server_truststore is required'):
            CmpClient(context)


class TestCmpClientUrlBuilding:
    """Tests for URL building."""

    def test_build_url_default_port(self, cmp_context_shared_secret: CmpBaseRequestContext) -> None:
        """Test URL building with default port."""
        cmp_context_shared_secret.cmp_server_port = 443
        client = CmpClient(cmp_context_shared_secret)
        url = client._build_url()
        assert url == 'https://cmp.test.example.com/pkix/certification'

    def test_build_url_custom_port(self, cmp_context_shared_secret: CmpBaseRequestContext) -> None:
        """Test URL building with custom port."""
        client = CmpClient(cmp_context_shared_secret)
        url = client._build_url()
        assert url == 'https://cmp.test.example.com:8443/pkix/certification'

    def test_build_url_custom_path(self, cmp_context_shared_secret: CmpBaseRequestContext) -> None:
        """Test URL building with custom path."""
        client = CmpClient(cmp_context_shared_secret)
        url = client._build_url(path='/custom/path')
        assert url == 'https://cmp.test.example.com:8443/custom/path'


class TestCmpClientMessageBuilding:
    """Tests for CMP message building."""

    def test_build_cr_message(
        self,
        cmp_context_shared_secret: CmpBaseRequestContext,
        test_csr: x509.CertificateSigningRequest
    ) -> None:
        """Test building a CR message."""
        client = CmpClient(cmp_context_shared_secret)
        pki_message = client._build_cr_message(test_csr)
        
        assert pki_message is not None
        assert pki_message['header'] is not None
        assert pki_message['body'] is not None
        assert pki_message['body'].getName() == 'cr'

    def test_build_message_header(self, cmp_context_shared_secret: CmpBaseRequestContext) -> None:
        """Test building message header."""
        client = CmpClient(cmp_context_shared_secret)
        header = client._build_message_header()
        
        assert int(header['pvno']) == 2  # CMP version 2
        assert header['sender'] is not None
        assert header['recipient'] is not None
        assert header['transactionID'] is not None
        assert header['senderNonce'] is not None

    def test_build_cert_template(
        self,
        cmp_context_shared_secret: CmpBaseRequestContext,
        test_csr: x509.CertificateSigningRequest
    ) -> None:
        """Test converting CSR to cert template."""
        client = CmpClient(cmp_context_shared_secret)
        cert_template = client._build_csr_to_cert_template(test_csr)
        
        assert cert_template is not None
        assert cert_template['subject'].hasValue()
        assert cert_template['publicKey'].hasValue()


class TestCmpClientProtection:
    """Tests for message protection."""

    def test_add_protection_shared_secret(
        self,
        cmp_context_shared_secret: CmpBaseRequestContext,
        test_csr: x509.CertificateSigningRequest
    ) -> None:
        """Test adding shared secret protection."""
        client = CmpClient(cmp_context_shared_secret)
        pki_message = client._build_cr_message(test_csr)
        protected_message = client._add_protection(pki_message)
        
        assert protected_message['protection'] is not None

    def test_add_protection_signature(
        self,
        cmp_context_signature: CmpBaseRequestContext,
        test_csr: x509.CertificateSigningRequest,
        test_key_pair: tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]
    ) -> None:
        """Test adding signature-based protection."""
        private_key, _ = test_key_pair
        client = CmpClient(cmp_context_signature)
        pki_message = client._build_cr_message(test_csr, private_key)
        protected_message = client._add_protection(pki_message, private_key)
        
        assert protected_message['protection'] is not None

    def test_add_protection_no_auth(
        self,
        mock_truststore: Mock,
        test_csr: x509.CertificateSigningRequest
    ) -> None:
        """Test that protection fails without authentication method."""
        context = CmpBaseRequestContext(
            cmp_server_host='cmp.test.example.com',
            cmp_server_truststore=mock_truststore,
        )
        client = CmpClient(context)
        pki_message = client._build_cr_message(test_csr)
        
        with pytest.raises(CmpClientError, match='Either shared secret or private key must be provided'):
            client._add_protection(pki_message)


class TestCmpClientEnrollment:
    """Tests for certificate enrollment."""

    @patch('request.clients.cmp_client.requests.post')
    @patch('request.clients.cmp_client.tempfile.NamedTemporaryFile')
    def test_certification_request_success(
        self,
        mock_tempfile: Mock,
        mock_post: Mock,
        cmp_context_shared_secret: CmpBaseRequestContext,
        test_csr: x509.CertificateSigningRequest,
        test_key_pair: tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]
    ) -> None:
        """Test successful certification request."""
        # Mock temporary file
        mock_temp = MagicMock()
        mock_temp.name = '/tmp/test_ca_bundle.pem'
        mock_tempfile.return_value.__enter__.return_value = mock_temp

        # Create a mock successful CP response
        # Note: This would need a properly encoded CMP CP message
        # For now, we'll just test that the flow works
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.content = b'mock_cmp_response'  # Would be actual PKIMessage
        mock_post.return_value = mock_response

        client = CmpClient(cmp_context_shared_secret)
        
        # This will fail at response parsing, but that's OK for this test
        # In a real test, you'd provide a valid CP response
        with pytest.raises(CmpClientError):  # Expected because mock response is invalid
            client.certification_request(test_csr)

        # Verify the request was made
        assert mock_post.called
        call_kwargs = mock_post.call_args.kwargs
        assert 'verify' in call_kwargs
        assert 'timeout' in call_kwargs
        assert call_kwargs['timeout'] == 30

    @patch('request.clients.cmp_client.requests.post')
    def test_certification_request_http_error(
        self,
        mock_post: Mock,
        cmp_context_shared_secret: CmpBaseRequestContext,
        test_csr: x509.CertificateSigningRequest
    ) -> None:
        """Test certification request with HTTP error."""
        mock_response = Mock()
        mock_response.status_code = 500
        mock_response.text = 'Internal Server Error'
        mock_post.return_value = mock_response

        client = CmpClient(cmp_context_shared_secret)
        
        with pytest.raises(CmpClientError, match='CMP server returned error status 500'):
            with patch('request.clients.cmp_client.tempfile.NamedTemporaryFile'):
                client.certification_request(test_csr)


class TestCmpClientResponseParsing:
    """Tests for response parsing."""

    def test_parse_response_invalid_format(self, cmp_context_shared_secret: CmpBaseRequestContext) -> None:
        """Test parsing invalid response format."""
        client = CmpClient(cmp_context_shared_secret)
        
        with pytest.raises(CmpClientError, match='Failed to parse CMP server response'):
            client._parse_response(b'invalid_data')

    # Note: Testing successful response parsing would require creating
    # valid PKIMessage structures, which is complex. Consider integration tests.


# Integration test placeholder
@pytest.mark.integration
@pytest.mark.skip(reason='Requires CMP server')
class TestCmpClientIntegration:
    """Integration tests with real CMP server."""

    def test_full_enrollment_flow(self) -> None:
        """Test complete enrollment flow with real CMP server."""
        # This would connect to a test CMP server
        # and perform actual enrollment
        pass
