# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Unit tests for the CMP client."""

from unittest.mock import Mock, patch

import pytest
from cryptography import x509

from request.clients.cmp_client import CmpClient, CmpClientError
from request.request_context import CmpBaseRequestContext


def _der(tag: int, value: bytes) -> bytes:
    """Build a DER TLV for the raw extraction tests."""
    length = len(value)
    if length < 128:
        encoded_length = bytes([length])
    else:
        length_bytes = length.to_bytes((length.bit_length() + 7) // 8, 'big')
        encoded_length = bytes([0x80 | len(length_bytes)]) + length_bytes
    return bytes([tag]) + encoded_length + value


def _raw_cmp_response(*, ca_pubs: bytes = b'', extra_certs: bytes = b'') -> bytes:
    """Build the CertRepMessage shape traversed by CmpClient."""
    issued_cert = _der(0x30, b'issued')
    certified_key_pair = _der(0x30, _der(0xA0, issued_cert))
    cert_response = _der(
        0x30,
        _der(0x02, b'\x00') + _der(0x30, _der(0x02, b'\x00')) + certified_key_pair,
    )
    responses = _der(0x30, cert_response)
    cert_rep_message = _der(0x30, ca_pubs + responses)
    body = _der(0x30, cert_rep_message)
    header = _der(0x30, b'')
    body_and_extra = header + body + extra_certs
    return _der(0x30, body_and_extra)


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

    @pytest.mark.parametrize(
        ('data', 'offset', 'message'),
        [
            (b'', 0, 'DER parse error: offset 0 beyond data length 0'),
            (b'\x30', 0, 'index out of range'),
        ],
    )
    def test_parse_der_tlv_malformed_or_truncated(
        self,
        valid_context: CmpBaseRequestContext,
        data: bytes,
        offset: int,
        message: str,
    ) -> None:
        """Test malformed and truncated DER length fields."""
        client = CmpClient(valid_context)

        with pytest.raises((ValueError, IndexError), match=message):
            client._parse_der_tlv(data, offset)

    def test_parse_der_tlv_preserves_declared_length_for_truncated_value(
        self, valid_context: CmpBaseRequestContext
    ) -> None:
        """Test the parser's declared-length result for an incomplete value."""
        client = CmpClient(valid_context)

        _, header_length, value_length, total_length = client._parse_der_tlv(b'\x30\x02\x00', 0)

        assert (header_length, value_length, total_length) == (2, 2, 4)

    def test_extract_certs_from_raw_response_navigates_real_der(self, valid_context: CmpBaseRequestContext) -> None:
        """Test extraction through the complete raw CertRepMessage structure."""
        client = CmpClient(valid_context)
        extra_one = _der(0x30, b'chain-one')
        extra_two = _der(0x30, b'chain-two')
        raw_response = _raw_cmp_response(
            ca_pubs=_der(0xA1, _der(0x30, b'ca-pub')),
            extra_certs=_der(0xA1, _der(0x30, extra_one + extra_two)),
        )

        issued_cert, extra_certs = client._extract_certs_from_raw_response(raw_response)

        assert issued_cert == _der(0x30, b'issued')
        assert extra_certs == [extra_one, extra_two]

    def test_extract_certs_from_raw_response_without_optional_fields(
        self, valid_context: CmpBaseRequestContext
    ) -> None:
        """Test extraction when caPubs and extraCerts are absent."""
        client = CmpClient(valid_context)

        issued_cert, extra_certs = client._extract_certs_from_raw_response(_raw_cmp_response())

        assert issued_cert == _der(0x30, b'issued')
        assert extra_certs == []

    def test_extract_certs_from_raw_response_raw_certificate_choice(
        self, valid_context: CmpBaseRequestContext
    ) -> None:
        """Test the fallback for an unexpected CertOrEncCert tag."""
        client = CmpClient(valid_context)
        raw_response = _raw_cmp_response()
        issued_cert = _der(0x30, b'issued')
        raw_response = raw_response.replace(_der(0xA0, issued_cert), issued_cert, 1)

        extracted_cert, extra_certs = client._extract_certs_from_raw_response(raw_response)

        assert extracted_cert == issued_cert
        assert extra_certs == []

    def test_extract_extra_certs_handles_non_sequence_wrapper(
        self, valid_context: CmpBaseRequestContext
    ) -> None:
        """Test extraction of an extra certificate from a non-SEQUENCE wrapper."""
        client = CmpClient(valid_context)
        extra_cert = _der(0xA0, b'extra')
        wrapped_extra_cert = _der(0xA1, extra_cert)

        extracted = client._extract_extra_certs(wrapped_extra_cert, 0, len(wrapped_extra_cert))

        assert extracted == [extra_cert]

    def test_extract_extra_certs_ignores_other_trailing_tlv(
        self, valid_context: CmpBaseRequestContext
    ) -> None:
        """Test that unrelated fields after the body are ignored."""
        client = CmpClient(valid_context)
        ignored_tlv = _der(0x30, b'ignored')

        extracted = client._extract_extra_certs(ignored_tlv, 0, len(ignored_tlv))

        assert extracted == []

    def test_skip_cert_req_id_and_status_requires_certified_key_pair(
        self, valid_context: CmpBaseRequestContext
    ) -> None:
        """Test the exact error for a CertResponse without a key pair."""
        client = CmpClient(valid_context)
        raw_cert_response = _der(0x02, b'\x00') + _der(0x30, b'')

        with pytest.raises(CmpClientError, match=r'^No certifiedKeyPair found in CertResponse$'):
            client._skip_cert_req_id_and_status(raw_cert_response, 0, len(raw_cert_response))

    @pytest.mark.parametrize(
        'raw_data',
        [b'', b'\x30', b'\x30\x02\x30'],
    )
    def test_extract_certs_from_raw_response_rejects_malformed_der(
        self, valid_context: CmpBaseRequestContext, raw_data: bytes
    ) -> None:
        """Test exact client errors for malformed raw CMP responses."""
        client = CmpClient(valid_context)

        with pytest.raises(CmpClientError, match=r'^Failed to extract certificates from raw CMP response DER:'):
            client._extract_certs_from_raw_response(raw_data)

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
    def test_send_pki_message_adds_shared_secret_protection(
        self, mock_encode, mock_post, valid_context: CmpBaseRequestContext
    ) -> None:
        """Test protected requests use the protected message for encoding."""
        client = CmpClient(valid_context)
        pki_message = Mock()
        protected_message = Mock()
        mock_encode.return_value = b'request_data'
        mock_response = Mock(status_code=200, content=b'response_data')
        mock_post.return_value = mock_response

        with patch.object(client, '_add_protection_shared_secret', return_value=protected_message) as add_protection:
            with patch.object(client, '_parse_response', return_value=Mock()):
                client.send_pki_message(pki_message, add_shared_secret_protection=True)

        add_protection.assert_called_once_with(pki_message)
        mock_encode.assert_called_once_with(protected_message)

    @patch('request.clients.cmp_client.requests.post')
    @patch('request.clients.cmp_client.encoder.encode')
    def test_send_pki_message_protection_error_is_preserved(
        self, mock_encode, mock_post, valid_context: CmpBaseRequestContext
    ) -> None:
        """Test protection failures retain their exact client error."""
        client = CmpClient(valid_context)
        protection_error = CmpClientError('CMP shared secret is not set')

        with patch.object(client, '_add_protection_shared_secret', side_effect=protection_error):
            with pytest.raises(CmpClientError, match=r'^CMP shared secret is not set$'):
                client.send_pki_message(Mock(), add_shared_secret_protection=True)

        mock_encode.assert_not_called()
        mock_post.assert_not_called()

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

        with pytest.raises(CmpClientError, match=r'^CMP server returned error status 500: Internal Server Error$'):
            client.send_pki_message(mock_pki_message)

    @patch('request.clients.cmp_client.requests.post')
    @patch('request.clients.cmp_client.encoder.encode')
    def test_send_pki_message_request_exception(self, mock_encode, mock_post, valid_context: CmpBaseRequestContext) -> None:
        """Test sending PKI message fails with request exception."""
        client = CmpClient(valid_context)

        import requests
        mock_post.side_effect = requests.exceptions.Timeout('Connection timed out')

        mock_pki_message = Mock()

        with pytest.raises(
            CmpClientError,
            match=r'^Failed to communicate with CMP server: Connection timed out$',
        ):
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

    def test_extract_issued_certificate_wraps_certificate_load_error(
        self, valid_context: CmpBaseRequestContext
    ) -> None:
        """Test invalid extracted certificate bytes produce the client error."""
        client = CmpClient(valid_context)
        mock_cert_response = Mock()
        mock_status = Mock()
        mock_status.__getitem__ = Mock(return_value=0)
        mock_cert_response.__getitem__ = Mock(return_value=mock_status)
        mock_body = Mock()
        mock_body.getName.return_value = 'cp'
        mock_cert_rep_message = Mock()
        mock_cert_rep_message.__getitem__ = Mock(return_value=[mock_cert_response])
        mock_body.__getitem__ = Mock(return_value=mock_cert_rep_message)
        mock_message = Mock()
        mock_message.__getitem__ = Mock(return_value=mock_body)

        with patch.object(client, '_extract_certs_from_raw_response', return_value=(b'bad', [])):
            with patch(
                'request.clients.cmp_client.x509.load_der_x509_certificate',
                side_effect=ValueError('invalid certificate'),
            ):
                with pytest.raises(
                    CmpClientError,
                    match=r'^Failed to extract certificate from response: invalid certificate$',
                ):
                    client._extract_issued_certificate(mock_message, b'raw_data')
