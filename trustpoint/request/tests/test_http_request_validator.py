# Copyright (c) 2025 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT


"""Unit tests for the HTTP request validation module."""
import base64
from unittest.mock import MagicMock

import pytest

from request.request_validator.http_req import (
    AcceptHeaderValidation,
    ClientCertificateValidation,
    CmpHttpRequestValidator,
    CompositeValidation,
    ContentTransferEncodingValidation,
    ContentTypeValidation,
    EstHttpRequestValidator,
    IntermediateCertificatesValidation,
    PayloadSizeValidation,
    TrustedProxyHeadersValidation,
)
from request.request_context import BaseRequestContext, EstCertificateRequestContext

# Sample PEM certificate for testing
SAMPLE_PEM_CERT = """-----BEGIN CERTIFICATE-----
MIIBkTCB+wIJAMlyFqk69v+9MA0GCSqGSIb3DQEBCwUAMBQxEjAQBgNVBAMMCWxv
Y2FsaG9zdDAeFw0yMzEyMDExMjAwMDBaFw0yNDEyMDExMjAwMDBaMBQxEjAQBgNV
BAMMCWxvY2FsaG9zdDBcMA0GCSqGSIb3DQEBAQUAA0sAMEgCQQDTwqq/oty2vJlX
yQtHFkoVQ+ZWGYDdmutU1qzTT5/3YQFJvPhlHT0JfJJ5Nc6MLHoFzqVrJ8vqS1Pk
J8wjqFi3AgMBAAEwDQYJKoZIhvcNAQELBQADQQBJlffJHybjDGxRMqaRmDhX0+6v
02q6FDpnOJMJQFRQXCpAMjWQjEhxhRLvjRHVzLkOhUzUoGcvQIlsUBKgQ+xJJqUd
-----END CERTIFICATE-----"""


class TestPayloadSizeValidation:
    """Test PayloadSizeValidation class."""

    def test_init(self):
        """Test initialization with max_payload_size."""
        validator = PayloadSizeValidation(max_payload_size=1024)
        assert validator.max_payload_size == 1024

    def test_validate_success(self):
        """Test successful validation with payload under limit."""
        validator = PayloadSizeValidation(max_payload_size=1024)
        context = BaseRequestContext()
        context.raw_message = MagicMock()
        context.raw_message.body = b'test payload'

        # Should not raise any exception
        validator.validate(context)

    def test_validate_missing_raw_message(self):
        """Test ValueError when raw_message is None."""
        validator = PayloadSizeValidation(max_payload_size=1024)
        context = BaseRequestContext()
        context.raw_message = None

        try:
            validator.validate(context)
            assert False, 'Expected ValueError to be raised'
        except ValueError as e:
            assert 'Raw message is missing from the context' in str(e)

    def test_validate_missing_body(self):
        """Test ValueError when body is missing."""
        validator = PayloadSizeValidation(max_payload_size=1024)
        context = BaseRequestContext()
        context.raw_message = MagicMock()
        context.raw_message.body = None

        try:
            validator.validate(context)
            assert False, 'Expected ValueError to be raised'
        except ValueError as e:
            assert 'Raw message is missing body' in str(e)

    def test_validate_payload_too_large(self):
        """Test ValueError when payload exceeds max size."""
        validator = PayloadSizeValidation(max_payload_size=10)
        context = BaseRequestContext()
        context.raw_message = MagicMock()
        context.raw_message.body = b'this payload is too large'

        try:
            validator.validate(context)
            assert False, 'Expected ValueError to be raised'
        except ValueError as e:
            assert 'Payload size exceeds maximum allowed size' in str(e)


class TestContentTypeValidation:
    """Test ContentTypeValidation class."""

    def test_init(self):
        """Test initialization with expected_content_type."""
        validator = ContentTypeValidation(expected_content_type='application/json')
        assert validator.expected_content_type == 'application/json'

    def test_validate_success(self):
        """Test successful validation with correct content type."""
        validator = ContentTypeValidation(expected_content_type='application/json')
        context = BaseRequestContext()
        context.raw_message = MagicMock()
        context.raw_message.headers = {'Content-Type': 'application/json'}

        # Should not raise any exception
        validator.validate(context)

    def test_validate_missing_raw_message(self):
        """Test ValueError when raw_message is None."""
        validator = ContentTypeValidation(expected_content_type='application/json')
        context = BaseRequestContext()
        context.raw_message = None

        try:
            validator.validate(context)
            assert False, 'Expected ValueError to be raised'
        except ValueError as e:
            assert 'Raw message is missing from the context' in str(e)

    def test_validate_missing_headers(self):
        """Test ValueError when headers are missing."""
        validator = ContentTypeValidation(expected_content_type='application/json')
        context = BaseRequestContext()
        context.raw_message = MagicMock()
        context.raw_message.headers = None

        try:
            validator.validate(context)
            assert False, 'Expected ValueError to be raised'
        except ValueError as e:
            assert 'Raw message is missing headers' in str(e)

    def test_validate_missing_content_type(self):
        """Test ValueError when Content-Type header is missing."""
        validator = ContentTypeValidation(expected_content_type='application/json')
        context = BaseRequestContext()
        context.raw_message = MagicMock()
        context.raw_message.headers = {'Other-Header': 'value'}

        try:
            validator.validate(context)
            assert False, 'Expected ValueError to be raised'
        except ValueError as e:
            assert "Missing 'Content-Type' header" in str(e)

    def test_validate_invalid_content_type(self):
        """Test ValueError when Content-Type doesn't match expected."""
        validator = ContentTypeValidation(expected_content_type='application/json')
        context = BaseRequestContext()
        context.raw_message = MagicMock()
        context.raw_message.headers = {'Content-Type': 'text/plain'}

        try:
            validator.validate(context)
            assert False, 'Expected ValueError to be raised'
        except ValueError as e:
            assert "Invalid 'Content-Type' header" in str(e)


class TestAcceptHeaderValidation:
    """Test AcceptHeaderValidation class."""

    def test_init(self):
        """Test initialization with allowed_content_types list."""
        allowed_types = ['application/json', 'application/xml']
        validator = AcceptHeaderValidation(allowed_content_types=allowed_types)
        assert validator.allowed_content_types == allowed_types

    def test_validate_success_single_type(self):
        """Test successful validation with single matching type."""
        validator = AcceptHeaderValidation(allowed_content_types=['application/json'])
        context = BaseRequestContext()
        context.raw_message = MagicMock()
        context.raw_message.headers = {'Accept': 'application/json'}

        # Should not raise any exception
        validator.validate(context)

    def test_validate_success_multiple_types(self):
        """Test successful validation with multiple types."""
        validator = AcceptHeaderValidation(allowed_content_types=['application/json', 'application/xml'])
        context = BaseRequestContext()
        context.raw_message = MagicMock()
        context.raw_message.headers = {'Accept': 'application/json, application/xml'}

        # Should not raise any exception
        validator.validate(context)

    def test_validate_missing_accept_header(self):
        """Test that missing Accept header passes validation."""
        validator = AcceptHeaderValidation(allowed_content_types=['application/json'])
        context = BaseRequestContext()
        context.raw_message = MagicMock()
        context.raw_message.headers = {'Other-Header': 'value'}

        # Should not raise any exception
        validator.validate(context)

    def test_validate_invalid_accept_header(self):
        """Test ValueError when Accept header doesn't match allowed types."""
        validator = AcceptHeaderValidation(allowed_content_types=['application/json'])
        context = BaseRequestContext()
        context.raw_message = MagicMock()
        context.raw_message.headers = {'Accept': 'text/plain'}

        try:
            validator.validate(context)
            assert False, 'Expected ValueError to be raised'
        except ValueError as e:
            assert "The provided 'Accept' header" in str(e)

    def test_validate_missing_raw_message(self):
        """Test ValueError when raw_message is None."""
        validator = AcceptHeaderValidation(allowed_content_types=['application/json'])
        context = BaseRequestContext()
        context.raw_message = None

        try:
            validator.validate(context)
            assert False, 'Expected ValueError to be raised'
        except ValueError as e:
            assert 'Raw message is missing from the context' in str(e)

    def test_validate_missing_headers(self):
        """Test ValueError when headers are missing."""
        validator = AcceptHeaderValidation(allowed_content_types=['application/json'])
        context = BaseRequestContext()
        context.raw_message = MagicMock()
        context.raw_message.headers = None

        try:
            validator.validate(context)
            assert False, 'Expected ValueError to be raised'
        except ValueError as e:
            assert 'Raw message is missing headers' in str(e)


class TestClientCertificateValidation:
    """Test ClientCertificateValidation class."""

    def test_validate_success(self, domain_credential_est_onboarding):
        """Test successful validation with valid PEM certificate."""
        domain_credential = domain_credential_est_onboarding.get('domain_credential')
        cert_pem = domain_credential.credential.certificate.cert_pem

        validator = ClientCertificateValidation()
        context = BaseRequestContext()
        context.raw_message = MagicMock()
        context.raw_message.headers = {'HTTP_SSL_CLIENT_CERT': cert_pem}
        context.raw_message.META = {'HTTP_SSL_CLIENT_CERT': cert_pem}

        validator.validate(context)
        assert context.client_certificate is not None

    def test_validate_missing_cert_header(self):
        """Test that missing HTTP_SSL_CLIENT_CERT header passes."""
        validator = ClientCertificateValidation()
        context = BaseRequestContext()
        context.raw_message = MagicMock()
        context.raw_message.headers = {'Other-Header': 'value'}
        context.raw_message.META = {'Other-Header': 'value'}

        validator.validate(context)

    def test_validate_invalid_certificate(self):
        """Test ValueError for invalid PEM certificate."""
        validator = ClientCertificateValidation()
        context = BaseRequestContext()
        context.raw_message = MagicMock()
        context.raw_message.headers = {'HTTP_SSL_CLIENT_CERT': 'invalid cert'}
        context.raw_message.META = {'HTTP_SSL_CLIENT_CERT': 'invalid cert'}

        try:
            validator.validate(context)
            assert False, 'Expected ValueError to be raised'
        except ValueError as e:
            assert 'Invalid HTTP_SSL_CLIENT_CERT header' in str(e)

    def test_validate_missing_raw_message(self):
        """Test ValueError when raw_message is None."""
        validator = ClientCertificateValidation()
        context = BaseRequestContext()
        context.raw_message = None

        try:
            validator.validate(context)
            assert False, 'Expected ValueError to be raised'
        except ValueError as e:
            assert 'Raw message is missing from the context' in str(e)

    def test_validate_missing_headers(self):
        """Test validation is skipped when headers/META are missing."""
        validator = ClientCertificateValidation()
        context = BaseRequestContext()
        context.raw_message = MagicMock()
        context.raw_message.headers = None
        context.raw_message.META = None

        validator.validate(context)

class TestIntermediateCertificatesValidation:
    """Test IntermediateCertificatesValidation class."""

    def test_validate_success_single_cert(self, domain_credential_est_onboarding):
        """Test successful validation with single intermediate cert."""
        domain_credential = domain_credential_est_onboarding.get('domain_credential')
        cert_pem = domain_credential.credential.certificate.cert_pem

        validator = IntermediateCertificatesValidation()
        context = BaseRequestContext()
        context.raw_message = MagicMock()
        context.raw_message.META = {'SSL_CLIENT_CERT_CHAIN_0': cert_pem}

        validator.validate(context)
        assert context.client_intermediate_certificate is not None
        assert len(context.client_intermediate_certificate) == 1

    def test_validate_success_multiple_certs(self, domain_credential_est_onboarding):
        """Test successful validation with multiple intermediate certs."""
        domain_credential = domain_credential_est_onboarding.get('domain_credential')
        cert_pem = domain_credential.credential.certificate.cert_pem

        validator = IntermediateCertificatesValidation()
        context = BaseRequestContext()
        context.raw_message = MagicMock()
        context.raw_message.META = {
            'SSL_CLIENT_CERT_CHAIN_0': cert_pem,
            'SSL_CLIENT_CERT_CHAIN_1': cert_pem,
        }

        validator.validate(context)
        assert context.client_intermediate_certificate is not None
        assert len(context.client_intermediate_certificate) == 2

    def test_validate_no_intermediate_certs(self):
        """Test that no intermediate certs sets context to None."""
        validator = IntermediateCertificatesValidation()
        context = BaseRequestContext()
        context.raw_message = MagicMock()
        context.raw_message.META = {}

        validator.validate(context)
        assert context.client_intermediate_certificate is None

    def test_validate_invalid_certificate(self):
        """Test ValueError for invalid PEM certificate."""
        validator = IntermediateCertificatesValidation()
        context = BaseRequestContext()
        context.raw_message = MagicMock()
        context.raw_message.META = {'SSL_CLIENT_CERT_CHAIN_0': 'invalid cert'}

        try:
            validator.validate(context)
            assert False, 'Expected ValueError to be raised'
        except ValueError as e:
            assert 'Invalid SSL client certificate chain entry 0' in str(e)

    def test_validate_missing_raw_message(self):
        """Test ValueError when raw_message is None."""
        validator = IntermediateCertificatesValidation()
        context = BaseRequestContext()
        context.raw_message = None

        try:
            validator.validate(context)
            assert False, 'Expected ValueError to be raised'
        except ValueError as e:
            assert 'Raw message is missing from the context' in str(e)


class TestContentTransferEncodingValidation:
    """Test ContentTransferEncodingValidation class."""

    def test_validate_success_base64(self):
        """Validate Base64 while leaving decoding to the message parser."""
        validator = ContentTransferEncodingValidation()
        context = BaseRequestContext()
        context.raw_message = MagicMock()
        context.raw_message.headers = {'Content-Transfer-Encoding': 'base64'}
        test_content = 'Hello World'
        encoded_content = base64.b64encode(test_content.encode())
        context.raw_message.body = encoded_content

        validator.validate(context)
        assert context.raw_message.body == encoded_content
        assert context.parsed_message is None

    def test_validate_no_encoding(self):
        """Test that missing Content-Transfer-Encoding header passes."""
        validator = ContentTransferEncodingValidation()
        context = BaseRequestContext()
        context.raw_message = MagicMock()
        context.raw_message.headers = {'Other-Header': 'value'}
        context.raw_message.body = b'test content'

        # Should not raise any exception
        validator.validate(context)

    def test_validate_non_base64_encoding(self):
        """Test that non-base64 encoding passes."""
        validator = ContentTransferEncodingValidation()
        context = BaseRequestContext()
        context.raw_message = MagicMock()
        context.raw_message.headers = {'Content-Transfer-Encoding': 'binary'}
        context.raw_message.body = b'test content'

        # Should not raise any exception
        validator.validate(context)

    def test_validate_invalid_base64(self):
        """Test ValueError for invalid base64 content."""
        validator = ContentTransferEncodingValidation()
        context = BaseRequestContext()
        context.raw_message = MagicMock()
        context.raw_message.headers = {'Content-Transfer-Encoding': 'base64'}
        context.raw_message.body = 'invalid base64 content with invalid characters: @#$%^&*()'

        try:
            validator.validate(context)
            assert False, 'Expected ValueError to be raised'
        except ValueError as e:
            assert 'Invalid base64 encoding in message' in str(e)

    def test_validate_missing_raw_message(self):
        """Test ValueError when raw_message is None."""
        validator = ContentTransferEncodingValidation()
        context = BaseRequestContext()
        context.raw_message = None

        try:
            validator.validate(context)
            assert False, 'Expected ValueError to be raised'
        except ValueError as e:
            assert 'Raw message is missing from the context' in str(e)

    def test_validate_missing_headers(self):
        """Test ValueError when headers are missing."""
        validator = ContentTransferEncodingValidation()
        context = BaseRequestContext()
        context.raw_message = MagicMock()
        context.raw_message.headers = None

        try:
            validator.validate(context)
            assert False, 'Expected ValueError to be raised'
        except ValueError as e:
            assert 'Raw message is missing headers' in str(e)

    def test_validate_missing_body(self):
        """Test ValueError when body is missing."""
        validator = ContentTransferEncodingValidation()
        context = BaseRequestContext()
        context.raw_message = MagicMock()
        context.raw_message.headers = {'Content-Transfer-Encoding': 'base64'}
        context.raw_message.body = None

        try:
            validator.validate(context)
            assert False, 'Expected ValueError to be raised'
        except ValueError as e:
            assert 'Raw message is missing body' in str(e)


class TestCompositeValidation:
    """Test CompositeValidation class."""

    def test_init(self):
        """Test initialization with empty components list."""
        validator = CompositeValidation()
        assert validator.components == []

    def test_add_component(self):
        """Test adding a component to the composite."""
        validator = CompositeValidation()
        component = PayloadSizeValidation(max_payload_size=1024)

        validator.add(component)
        assert len(validator.components) == 1
        assert validator.components[0] == component

    def test_remove_component(self):
        """Test removing a component from the composite."""
        validator = CompositeValidation()
        component = PayloadSizeValidation(max_payload_size=1024)
        validator.add(component)

        validator.remove(component)
        assert len(validator.components) == 0

    def test_validate_all_components(self):
        """Test that all components are validated."""
        validator = CompositeValidation()
        mock_component1 = MagicMock()
        mock_component2 = MagicMock()

        validator.add(mock_component1)
        validator.add(mock_component2)

        context = BaseRequestContext()
        validator.validate(context)

        mock_component1.validate.assert_called_once_with(context)
        mock_component2.validate.assert_called_once_with(context)

    def test_validate_component_failure(self):
        """Test that component failure propagates."""
        validator = CompositeValidation()
        mock_component = MagicMock()
        mock_component.validate.side_effect = ValueError('Component failed')

        validator.add(mock_component)

        context = BaseRequestContext()
        try:
            validator.validate(context)
            assert False, 'Expected ValueError to be raised'
        except ValueError as e:
            assert 'Component failed' in str(e)


class TestCmpHttpRequestValidator:
    """Test CmpHttpRequestValidator class."""

    def test_init(self):
        """Test initialization with correct components."""
        validator = CmpHttpRequestValidator()
        assert len(validator.components) == 3
        assert isinstance(validator.components[0], TrustedProxyHeadersValidation)
        assert isinstance(validator.components[1], PayloadSizeValidation)
        assert isinstance(validator.components[2], ContentTypeValidation)
        assert validator.components[1].max_payload_size == 131072
        assert validator.components[2].expected_content_type == 'application/pkixcmp'

    def test_validate_integration(self, rf):
        """Test integration with valid CMP request."""
        validator = CmpHttpRequestValidator()
        context = BaseRequestContext()
        context.raw_message = rf.post('/', data=b'test cmp payload', content_type='application/pkixcmp')

        # Should not raise any exception
        validator.validate(context)


class TestEstHttpRequestValidator:
    """Test EstHttpRequestValidator class."""

    def test_init(self):
        """Test initialization with correct components."""
        validator = EstHttpRequestValidator()
        assert len(validator.components) == 7
        assert isinstance(validator.components[0], TrustedProxyHeadersValidation)
        assert isinstance(validator.components[1], PayloadSizeValidation)
        assert isinstance(validator.components[2], ContentTypeValidation)
        assert isinstance(validator.components[3], AcceptHeaderValidation)
        assert isinstance(validator.components[4], ClientCertificateValidation)
        assert isinstance(validator.components[5], IntermediateCertificatesValidation)
        assert isinstance(validator.components[6], ContentTransferEncodingValidation)

    def test_validate_integration(self):
        """Test integration with valid EST request."""
        validator = EstHttpRequestValidator()
        context = EstCertificateRequestContext()
        context.raw_message = MagicMock()
        context.raw_message.body = b'test est payload'
        context.raw_message.headers = {
            'Content-Type': 'application/pkcs10',
            'Accept': 'application/pkcs7-mime'
        }
        context.raw_message.META = {}

        validator.validate(context)


@pytest.mark.parametrize(
    ('validator_type', 'content_type'),
    [(CmpHttpRequestValidator, 'application/pkixcmp'), (EstHttpRequestValidator, 'application/pkcs10')],
)
@pytest.mark.parametrize('remote_addr', ['198.51.100.10', '', 'invalid-peer'])
def test_enrollment_rejects_proxy_headers_from_untrusted_or_invalid_peers(
    rf, settings, validator_type, content_type, remote_addr
):
    """A forwarded loopback address cannot override the untrusted direct peer."""
    settings.TRUSTPOINT_TRUSTED_PROXY_IPS = ('127.0.0.1', '::1')
    context = EstCertificateRequestContext()
    context.raw_message = rf.post(
        '/', data=b'payload', content_type=content_type,
        REMOTE_ADDR=remote_addr, HTTP_X_FORWARDED_FOR='127.0.0.1',
    )
    with pytest.raises(ValueError, match='TrustedProxyHeadersValidation'):
        validator_type().validate(context)


def test_configured_proxy_network_can_supply_forwarded_headers(rf, settings):
    """A direct peer in the configured network may supply proxy headers."""
    settings.TRUSTPOINT_TRUSTED_PROXY_IPS = '198.51.100.0/24'
    context = EstCertificateRequestContext()
    context.raw_message = rf.post(
        '/', data=b'payload', content_type='application/pkcs10',
        REMOTE_ADDR='198.51.100.10', HTTP_X_FORWARDED_FOR='203.0.113.10',
    )
    EstHttpRequestValidator().validate(context)
