"""Unit tests for the CMP client."""

from unittest.mock import Mock, patch

import pytest
from cryptography import x509
from pyasn1.codec.der import encoder
from pyasn1.type import tag, univ
from pyasn1_modules import rfc4210

from request.clients.cmp_client import CmpClient, CmpClientError
from request.request_context import CmpBaseRequestContext


class TestCmpClient:
    """Test cases for the CmpClient class."""

    @pytest.fixture
    def valid_context(self) -> CmpBaseRequestContext:
        """Create a valid CMP base request context."""
        return CmpBaseRequestContext(
            cmp_server_host='example.com',
            cmp_server_port=443,
            cmp_server_path='/pkix/certification',
            cmp_shared_secret='test_secret'
        )

    @pytest.fixture
    def minimal_context(self) -> CmpBaseRequestContext:
        """Create a minimal valid CMP base request context."""
        return CmpBaseRequestContext(
            cmp_server_host='example.com'
        )

    def test_init_valid_context(self, valid_context: CmpBaseRequestContext) -> None:
        """Test initialization with a valid context."""
        client = CmpClient(valid_context)
        assert client.context == valid_context
        assert client.timeout == 30

    def test_init_custom_timeout(self, valid_context: CmpBaseRequestContext) -> None:
        """Test initialization with custom timeout."""
        client = CmpClient(valid_context, timeout=60)
        assert client.timeout == 60

    def test_init_missing_host(self) -> None:
        """Test initialization fails when cmp_server_host is missing."""
        context = CmpBaseRequestContext()
        with pytest.raises(CmpClientError, match='cmp_server_host is required'):
            CmpClient(context)

    def test_init_none_host(self) -> None:
        """Test initialization fails when cmp_server_host is None."""
        context = CmpBaseRequestContext(cmp_server_host=None)
        with pytest.raises(CmpClientError, match='cmp_server_host is required'):
            CmpClient(context)

    def test_build_url_default_port(self, minimal_context: CmpBaseRequestContext) -> None:
        """Test URL building with default port."""
        client = CmpClient(minimal_context)
        url = client._build_url()
        assert url == 'https://example.comNone'

    def test_build_url_custom_port(self, valid_context: CmpBaseRequestContext) -> None:
        """Test URL building with custom port."""
        client = CmpClient(valid_context)
        url = client._build_url()
        assert url == 'https://example.com/pkix/certification'

    def test_build_url_non_default_port(self) -> None:
        """Test URL building with non-default port."""
        context = CmpBaseRequestContext(
            cmp_server_host='example.com',
            cmp_server_port=8443,
            cmp_server_path='/custom/path'
        )
        client = CmpClient(context)
        url = client._build_url()
        assert url == 'https://example.com:8443/custom/path'

    def test_build_url_no_path(self) -> None:
        """Test URL building with no custom path."""
        context = CmpBaseRequestContext(
            cmp_server_host='example.com',
            cmp_server_port=8080
        )
        client = CmpClient(context)
        url = client._build_url()
        assert url == 'https://example.com:8080None'

    @patch('request.clients.cmp_client.encoder.encode')
    def test_add_protection_shared_secret_missing_secret(self, mock_encode, minimal_context: CmpBaseRequestContext) -> None:
        """Test adding protection fails when shared secret is missing."""
        client = CmpClient(minimal_context)
        pki_message = Mock()

        with pytest.raises(CmpClientError, match='CMP shared secret is not set'):
            client._add_protection_shared_secret(pki_message)

    @patch('request.clients.cmp_client.encoder.encode')
    def test_add_protection_shared_secret_invalid_algorithm(self, mock_encode, valid_context: CmpBaseRequestContext) -> None:
        """Test adding protection fails with unsupported algorithm."""
        client = CmpClient(valid_context)
        
        # Create a mock that supports item access
        class MockPKIMessage(dict):
            def __getitem__(self, key):
                if key == 'header':
                    return {'protectionAlg': {'parameters': 'dummy'}}
                return super().__getitem__(key)
        
        pki_message = MockPKIMessage()

        # Mock the PBM parameter decoding
        class MockPBM(dict):
            def getName(self):
                return 'pbmParameter'
            
            def __getitem__(self, key):
                if key == 'salt':
                    return b'salt123'
                elif key == 'iterationCount':
                    return 1000
                elif key == 'owf':
                    return {'algorithm': Mock(prettyPrint=Mock(return_value='invalid_oid'))}
                elif key == 'mac':
                    return {'algorithm': Mock(prettyPrint=Mock(return_value='1.2.3.4.5'))}
                return super().__getitem__(key)
        
        mock_pbm = MockPBM()

        with patch('request.clients.cmp_client.decoder.decode') as mock_decode:
            mock_decode.return_value = (mock_pbm, None)

            with pytest.raises(CmpClientError, match='Unsupported OWF algorithm'):
                client._add_protection_shared_secret(pki_message)

    def test_parse_response_success(self, valid_context: CmpBaseRequestContext) -> None:
        """Test parsing a successful CMP response."""
        client = CmpClient(valid_context)

        # Create a mock PKI message with 'cp' body
        mock_body = Mock()
        mock_body.getName.return_value = 'cp'
        mock_message = Mock()
        mock_message.__getitem__ = Mock(return_value=mock_body)

        with patch('request.clients.cmp_client.decoder.decode') as mock_decode:
            mock_decode.return_value = (mock_message, None)

            result = client._parse_response(b'dummy_data')
            assert result == mock_message

    def test_parse_response_error(self, valid_context: CmpBaseRequestContext) -> None:
        """Test parsing a CMP error response."""
        client = CmpClient(valid_context)

        # Create a mock error message
        mock_status_string = Mock()
        mock_status_string.hasValue.return_value = True
        mock_status_string.__len__ = Mock(return_value=1)
        mock_status_string.getComponentByPosition.return_value = 'Test error'
        
        class MockPKIStatus(dict):
            def __getitem__(self, key):
                if key == 'status':
                    return 1
                elif key == 'statusString':
                    return mock_status_string
                return super().__getitem__(key)
        
        mock_pki_status = MockPKIStatus()
        
        mock_error = Mock()
        mock_error.__getitem__ = Mock(return_value=mock_pki_status)
        
        mock_body = Mock()
        mock_body.getName.return_value = 'error'
        mock_body.__getitem__ = Mock(return_value=mock_error)
        
        mock_message = Mock()
        mock_message.__getitem__ = Mock(return_value=mock_body)

        with patch('request.clients.cmp_client.decoder.decode') as mock_decode:
            mock_decode.return_value = (mock_message, None)

            with pytest.raises(CmpClientError, match='CMP server returned error status 1: Test error'):
                client._parse_response(b'dummy_data')

    def test_parse_der_tlv_simple(self, valid_context: CmpBaseRequestContext) -> None:
        """Test parsing a simple DER TLV element."""
        client = CmpClient(valid_context)

        # SEQUENCE tag (0x30) with length 2, data 0x0102
        data = b'\x30\x02\x01\x02'
        tag_byte, hdr_len, val_len, total_len = client._parse_der_tlv(data, 0)

        assert tag_byte == 0x30
        assert hdr_len == 2
        assert val_len == 2
        assert total_len == 4

    def test_parse_der_tlv_long_length(self, valid_context: CmpBaseRequestContext) -> None:
        """Test parsing DER TLV with long length encoding."""
        client = CmpClient(valid_context)

        # Tag 0x30, long length (0x81 indicates 1 byte length), length 0x80, data of 128 bytes
        data = b'\x30\x81\x80' + b'\x00' * 128
        tag_byte, hdr_len, val_len, total_len = client._parse_der_tlv(data, 0)

        assert tag_byte == 0x30
        assert hdr_len == 3  # tag(1) + length byte(1) + length value(1)
        assert val_len == 128
        assert total_len == 131

    def test_parse_der_tlv_offset_beyond_length(self, valid_context: CmpBaseRequestContext) -> None:
        """Test parsing DER TLV fails when offset is beyond data length."""
        client = CmpClient(valid_context)

        data = b'\x30\x02\x01\x02'
        with pytest.raises(ValueError, match='DER parse error: offset 5 beyond data length 4'):
            client._parse_der_tlv(data, 5)

    @patch('request.clients.cmp_client.requests.post')
    @patch('request.clients.cmp_client.encoder.encode')
    def test_send_pki_message_success(self, mock_encode, mock_post, valid_context: CmpBaseRequestContext) -> None:
        """Test sending a PKI message successfully."""
        client = CmpClient(valid_context)

        # Mock successful response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.content = b'response_data'
        mock_post.return_value = mock_response

        # Mock PKI message
        mock_pki_message = Mock()
        mock_parsed_response = Mock()

        with patch.object(client, '_parse_response') as mock_parse:
            mock_parse.return_value = mock_parsed_response

            result_message, result_raw = client.send_pki_message(mock_pki_message)

            assert result_message == mock_parsed_response
            assert result_raw == b'response_data'
            mock_post.assert_called_once()

    @patch('request.clients.cmp_client.requests.post')
    @patch('request.clients.cmp_client.encoder.encode')
    def test_send_pki_message_http_error(self, mock_encode, mock_post, valid_context: CmpBaseRequestContext) -> None:
        """Test sending PKI message fails with HTTP error."""
        client = CmpClient(valid_context)

        mock_response = Mock()
        mock_response.status_code = 500
        mock_response.text = 'Internal Server Error'
        mock_post.return_value = mock_response

        mock_pki_message = Mock()

        with pytest.raises(CmpClientError, match='CMP server returned error status 500'):
            client.send_pki_message(mock_pki_message)

    @patch('request.clients.cmp_client.requests.post')
    @patch('request.clients.cmp_client.encoder.encode')
    def test_send_pki_message_request_exception(self, mock_encode, mock_post, valid_context: CmpBaseRequestContext) -> None:
        """Test sending PKI message fails with request exception."""
        client = CmpClient(valid_context)

        import requests
        mock_post.side_effect = requests.exceptions.Timeout('Connection timed out')

        mock_pki_message = Mock()

        with pytest.raises(CmpClientError, match='Failed to communicate with CMP server'):
            client.send_pki_message(mock_pki_message)

    @patch.object(CmpClient, 'send_pki_message')
    @patch.object(CmpClient, '_extract_issued_certificate')
    def test_send_and_extract_certificate(self, mock_extract, mock_send, valid_context: CmpBaseRequestContext) -> None:
        """Test the convenience method for sending and extracting certificate."""
        client = CmpClient(valid_context)

        mock_pki_message = Mock()
        mock_response_message = Mock()
        mock_raw_response = b'raw_data'
        mock_certificate = Mock(spec=x509.Certificate)
        mock_chain = [Mock(spec=x509.Certificate)]

        mock_send.return_value = (mock_response_message, mock_raw_response)
        mock_extract.return_value = (mock_certificate, mock_chain)

        result_cert, result_chain = client.send_and_extract_certificate(mock_pki_message)

        assert result_cert == mock_certificate
        assert result_chain == mock_chain
        mock_send.assert_called_once_with(mock_pki_message, add_shared_secret_protection=False)
        mock_extract.assert_called_once_with(mock_response_message, mock_raw_response)

    @patch.object(CmpClient, 'send_pki_message')
    @patch.object(CmpClient, '_extract_issued_certificate')
    def test_send_and_extract_certificate_with_protection(self, mock_extract, mock_send, valid_context: CmpBaseRequestContext) -> None:
        """Test sending and extracting certificate with shared secret protection."""
        client = CmpClient(valid_context)

        mock_pki_message = Mock()
        mock_response_message = Mock()
        mock_raw_response = b'raw_data'
        mock_certificate = Mock(spec=x509.Certificate)
        mock_chain = [Mock(spec=x509.Certificate)]

        mock_send.return_value = (mock_response_message, mock_raw_response)
        mock_extract.return_value = (mock_certificate, mock_chain)

        result_cert, result_chain = client.send_and_extract_certificate(
            mock_pki_message, add_shared_secret_protection=True
        )

        assert result_cert == mock_certificate
        assert result_chain == mock_chain
        mock_send.assert_called_once_with(mock_pki_message, add_shared_secret_protection=True)

    def test_extract_issued_certificate_success(self, valid_context: CmpBaseRequestContext) -> None:
        """Test extracting issued certificate from successful response."""
        client = CmpClient(valid_context)

        # Mock response message
        mock_cert_response = Mock()
        mock_status = Mock()
        mock_status.__getitem__ = Mock(return_value=0)  # status = 0 (accepted)
        mock_cert_response.__getitem__ = Mock(return_value=mock_status)
        
        mock_body = Mock()
        mock_body.getName.return_value = 'cp'
        mock_cert_rep_message = Mock()
        mock_cert_rep_message.__getitem__ = Mock(return_value=[mock_cert_response])
        mock_body.__getitem__ = Mock(return_value=mock_cert_rep_message)
        
        mock_message = Mock()
        mock_message.__getitem__ = Mock(return_value=mock_body)

        # Mock certificate extraction
        mock_cert_der = b'cert_der_data'
        mock_chain_der = [b'chain_der_data']

        with patch.object(client, '_extract_certs_from_raw_response') as mock_extract:
            with patch('request.clients.cmp_client.x509.load_der_x509_certificate') as mock_load:
                mock_extract.return_value = (mock_cert_der, mock_chain_der)
                mock_cert = Mock(spec=x509.Certificate)
                mock_chain_cert = Mock(spec=x509.Certificate)
                mock_load.side_effect = [mock_cert, mock_chain_cert]

                result_cert, result_chain = client._extract_issued_certificate(mock_message, b'raw_data')

                assert result_cert == mock_cert
                assert result_chain == [mock_chain_cert]

    def test_extract_issued_certificate_failure_status(self, valid_context: CmpBaseRequestContext) -> None:
        """Test extracting certificate fails when status indicates failure."""
        client = CmpClient(valid_context)

        # Mock response with failure status
        mock_cert_response = Mock()
        mock_status = Mock()
        mock_status.__getitem__ = Mock(return_value=1)  # status = 1 (rejected)
        mock_status.get = Mock(return_value='Rejected')
        mock_cert_response.__getitem__ = Mock(return_value=mock_status)
        
        mock_body = Mock()
        mock_body.getName.return_value = 'cp'
        mock_cert_rep_message = Mock()
        mock_cert_rep_message.__getitem__ = Mock(return_value=[mock_cert_response])
        mock_body.__getitem__ = Mock(return_value=mock_cert_rep_message)
        
        mock_message = Mock()
        mock_message.__getitem__ = Mock(return_value=mock_body)

        with pytest.raises(CmpClientError, match='Certificate issuance failed with status 1'):
            client._extract_issued_certificate(mock_message, b'raw_data')

    def test_extract_issued_certificate_wrong_body_type(self, valid_context: CmpBaseRequestContext) -> None:
        """Test extracting certificate fails with wrong body type."""
        client = CmpClient(valid_context)

        mock_body = Mock()
        mock_body.getName.return_value = 'invalid'
        mock_message = Mock()
        mock_message.__getitem__ = Mock(return_value=mock_body)

        with pytest.raises(CmpClientError, match='Expected CP or IP response, got: invalid'):
            client._extract_issued_certificate(mock_message, b'raw_data')

    def test_extract_issued_certificate_no_responses(self, valid_context: CmpBaseRequestContext) -> None:
        """Test extracting certificate fails when no certificate responses."""
        client = CmpClient(valid_context)

        mock_body = Mock()
        mock_body.getName.return_value = 'cp'
        mock_cert_rep_message = Mock()
        mock_cert_rep_message.__getitem__ = Mock(return_value=[])
        mock_body.__getitem__ = Mock(return_value=mock_cert_rep_message)
        
        mock_message = Mock()
        mock_message.__getitem__ = Mock(return_value=mock_body)

        with pytest.raises(CmpClientError, match='No certificate responses in CMP message'):
            client._extract_issued_certificate(mock_message, b'raw_data')
