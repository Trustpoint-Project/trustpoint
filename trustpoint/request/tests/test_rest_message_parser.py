"""Tests for REST API PKI message parser components."""

from __future__ import annotations

import base64
import json
from unittest.mock import Mock, patch

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.serialization import Encoding

from request.message_parser.rest import (
    RestAuthorizationHeaderParsing,
    RestCsrSignatureVerification,
    RestMessageParser,
    RestPkiMessageParsing,
)
from request.request_context import RestBaseRequestContext, RestCertificateRequestContext


def _make_ec_csr() -> x509.CertificateSigningRequest:
    """Return a self-signed EC P-256 CSR for testing."""
    key = ec.generate_private_key(ec.SECP256R1())
    return (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, 'test')]))
        .sign(key, hashes.SHA256())
    )


def _make_rsa_csr() -> x509.CertificateSigningRequest:
    """Return a self-signed RSA-2048 CSR for testing."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, 'rsa-test')]))
        .sign(key, hashes.SHA256())
    )


# ---------------------------------------------------------------------------
# RestAuthorizationHeaderParsing
# ---------------------------------------------------------------------------


class TestRestAuthorizationHeaderParsing:
    """Tests for RestAuthorizationHeaderParsing.parse."""

    def _ctx(self, auth_value: str | None = None, headers: dict | None = None) -> RestBaseRequestContext:
        """Build a RestBaseRequestContext with a mocked raw_message."""
        ctx = RestBaseRequestContext()
        req = Mock()
        req.headers = headers if headers is not None else (
            {'Authorization': auth_value} if auth_value is not None else {}
        )
        ctx.raw_message = req
        return ctx

    def test_wrong_context_type_raises_type_error(self) -> None:
        """Non-RestBaseRequestContext raises TypeError."""
        from request.request_context import BaseRequestContext
        ctx = Mock(spec=BaseRequestContext)
        with pytest.raises(TypeError, match='RestAuthorizationHeaderParsing requires'):
            RestAuthorizationHeaderParsing().parse(ctx)

    def test_missing_raw_message_raises_value_error(self) -> None:
        """None raw_message raises ValueError."""
        ctx = RestBaseRequestContext()
        ctx.raw_message = None
        with pytest.raises(ValueError, match='Raw message is missing from the context'):
            RestAuthorizationHeaderParsing().parse(ctx)

    def test_none_headers_raises_value_error(self) -> None:
        """None headers attribute raises ValueError."""
        ctx = RestBaseRequestContext()
        req = Mock()
        req.headers = None
        ctx.raw_message = req
        with pytest.raises(ValueError, match='Raw message is missing headers'):
            RestAuthorizationHeaderParsing().parse(ctx)

    def test_no_authorization_header_is_a_noop(self) -> None:
        """Missing Authorization header leaves context unchanged."""
        ctx = self._ctx(headers={'Content-Type': 'application/json'})
        RestAuthorizationHeaderParsing().parse(ctx)
        assert ctx.rest_username is None
        assert ctx.rest_password is None

    def test_bearer_scheme_raises_value_error(self) -> None:
        """Non-Basic Authorization scheme raises ValueError."""
        ctx = self._ctx('Bearer token123')
        with pytest.raises(ValueError, match="must start with 'Basic'"):
            RestAuthorizationHeaderParsing().parse(ctx)

    def test_valid_basic_auth_extracts_username_and_password(self) -> None:
        """Valid Basic auth populates rest_username and rest_password on the context."""
        encoded = base64.b64encode(b'alice:secret').decode()
        ctx = self._ctx(f'Basic {encoded}')
        RestAuthorizationHeaderParsing().parse(ctx)
        assert ctx.rest_username == 'alice'
        assert ctx.rest_password == 'secret'

    def test_password_containing_colon_is_preserved_in_full(self) -> None:
        """Password with embedded colons is kept intact after the first colon separator."""
        encoded = base64.b64encode(b'user:pass:with:colons').decode()
        ctx = self._ctx(f'Basic {encoded}')
        RestAuthorizationHeaderParsing().parse(ctx)
        assert ctx.rest_username == 'user'
        assert ctx.rest_password == 'pass:with:colons'

    def test_malformed_base64_raises_value_error(self) -> None:
        """Invalid Base64 credentials raise ValueError."""
        ctx = self._ctx('Basic !!!not_valid_base64!!!')
        with pytest.raises(ValueError, match="Malformed 'Authorization' header"):
            RestAuthorizationHeaderParsing().parse(ctx)


# ---------------------------------------------------------------------------
# RestPkiMessageParsing
# ---------------------------------------------------------------------------


class TestRestPkiMessageParsing:
    """Tests for RestPkiMessageParsing.parse."""

    def _ctx(self, body: bytes | None) -> RestCertificateRequestContext:
        """Build a RestCertificateRequestContext with the given request body."""
        ctx = RestCertificateRequestContext()
        req = Mock()
        req.body = body
        ctx.raw_message = req
        return ctx

    def _json_body(self, csr_value: str) -> bytes:
        return json.dumps({'csr': csr_value}).encode()

    def test_wrong_context_type_raises_type_error(self) -> None:
        """Non-RestCertificateRequestContext raises TypeError."""
        ctx = Mock(spec=RestBaseRequestContext)
        with pytest.raises(TypeError, match='RestPkiMessageParsing requires'):
            RestPkiMessageParsing().parse(ctx)

    def test_missing_raw_message_raises_value_error(self) -> None:
        """None raw_message raises ValueError."""
        ctx = RestCertificateRequestContext()
        ctx.raw_message = None
        with pytest.raises(ValueError, match='Raw message is missing from the context'):
            RestPkiMessageParsing().parse(ctx)

    def test_empty_body_raises_value_error(self) -> None:
        """Empty (falsy) body raises ValueError."""
        ctx = self._ctx(b'')
        with pytest.raises(ValueError, match='Raw message is missing body'):
            RestPkiMessageParsing().parse(ctx)

    def test_invalid_json_raises_value_error(self) -> None:
        """Non-JSON body raises ValueError."""
        ctx = self._ctx(b'not json {')
        with pytest.raises(ValueError, match='Failed to parse JSON body'):
            RestPkiMessageParsing().parse(ctx)

    def test_missing_csr_field_raises_value_error(self) -> None:
        """JSON body without the 'csr' key raises ValueError."""
        ctx = self._ctx(json.dumps({'other': 'value'}).encode())
        with pytest.raises(ValueError, match="Missing 'csr' field"):
            RestPkiMessageParsing().parse(ctx)

    def test_pem_csr_is_parsed_and_stored(self) -> None:
        """PEM-encoded CSR in JSON body is parsed and stored in context.cert_requested."""
        csr = _make_ec_csr()
        pem_str = csr.public_bytes(Encoding.PEM).decode()
        ctx = self._ctx(self._json_body(pem_str))
        RestPkiMessageParsing().parse(ctx)
        assert isinstance(ctx.cert_requested, x509.CertificateSigningRequest)

    def test_base64_der_csr_is_parsed_and_stored(self) -> None:
        """Base64-DER-encoded CSR in JSON body is parsed and stored in context."""
        csr = _make_ec_csr()
        b64_str = base64.b64encode(csr.public_bytes(Encoding.DER)).decode()
        ctx = self._ctx(self._json_body(b64_str))
        RestPkiMessageParsing().parse(ctx)
        assert isinstance(ctx.cert_requested, x509.CertificateSigningRequest)

    def test_rsa_csr_is_accepted(self) -> None:
        """RSA CSR in JSON body is parsed correctly."""
        csr = _make_rsa_csr()
        pem_str = csr.public_bytes(Encoding.PEM).decode()
        ctx = self._ctx(self._json_body(pem_str))
        RestPkiMessageParsing().parse(ctx)
        assert isinstance(ctx.cert_requested, x509.CertificateSigningRequest)

    def test_garbage_csr_value_raises_value_error(self) -> None:
        """A 'csr' value that is not valid PEM or DER raises ValueError."""
        ctx = self._ctx(self._json_body('ZZZ_garbage_ZZZ'))
        with pytest.raises(ValueError, match='Failed to parse the CSR'):
            RestPkiMessageParsing().parse(ctx)

    def test_string_body_is_accepted(self) -> None:
        """A string (not bytes) body is also accepted."""
        csr = _make_ec_csr()
        pem_str = csr.public_bytes(Encoding.PEM).decode()
        ctx = RestCertificateRequestContext()
        req = Mock()
        req.body = json.dumps({'csr': pem_str})  # str, not bytes
        ctx.raw_message = req
        RestPkiMessageParsing().parse(ctx)
        assert isinstance(ctx.cert_requested, x509.CertificateSigningRequest)


# ---------------------------------------------------------------------------
# RestCsrSignatureVerification
# ---------------------------------------------------------------------------


class TestRestCsrSignatureVerification:
    """Tests for RestCsrSignatureVerification.parse."""

    def test_wrong_context_type_raises_type_error(self) -> None:
        """Non-RestCertificateRequestContext raises TypeError."""
        ctx = Mock(spec=RestBaseRequestContext)
        with pytest.raises(TypeError, match='RestCsrSignatureVerification requires'):
            RestCsrSignatureVerification().parse(ctx)

    def test_missing_csr_raises_value_error(self) -> None:
        """None cert_requested raises ValueError."""
        ctx = RestCertificateRequestContext()
        ctx.cert_requested = None
        with pytest.raises(ValueError, match='CSR not found in the parsing context'):
            RestCsrSignatureVerification().parse(ctx)

    def test_wrong_csr_type_raises_type_error(self) -> None:
        """Non-CertificateSigningRequest cert_requested raises TypeError."""
        ctx = RestCertificateRequestContext()
        ctx.cert_requested = 'not a csr'  # type: ignore[assignment]
        with pytest.raises(TypeError, match='Expected a CertificateSigningRequest object'):
            RestCsrSignatureVerification().parse(ctx)

    def test_no_signature_hash_algorithm_raises_value_error(self) -> None:
        """CSR with signature_hash_algorithm=None raises ValueError."""
        ctx = RestCertificateRequestContext()
        mock_csr = Mock(spec=x509.CertificateSigningRequest)
        mock_csr.signature_hash_algorithm = None
        ctx.cert_requested = mock_csr
        with pytest.raises(ValueError, match='does not contain a signature hash algorithm'):
            RestCsrSignatureVerification().parse(ctx)

    def test_unsupported_key_type_raises_type_error(self) -> None:
        """DSA or other unsupported public key types raise TypeError."""
        ctx = RestCertificateRequestContext()
        mock_csr = Mock(spec=x509.CertificateSigningRequest)
        mock_csr.signature_hash_algorithm = hashes.SHA256()
        mock_csr.public_key.return_value = Mock()  # not RSA or EC
        ctx.cert_requested = mock_csr
        with pytest.raises(TypeError, match='Unsupported public key type'):
            RestCsrSignatureVerification().parse(ctx)

    def test_valid_ec_csr_passes(self) -> None:
        """A correctly signed EC CSR passes signature verification without raising."""
        ctx = RestCertificateRequestContext()
        ctx.cert_requested = _make_ec_csr()
        RestCsrSignatureVerification().parse(ctx)

    def test_valid_rsa_csr_passes(self) -> None:
        """A correctly signed RSA CSR passes signature verification without raising."""
        ctx = RestCertificateRequestContext()
        ctx.cert_requested = _make_rsa_csr()
        RestCsrSignatureVerification().parse(ctx)

    def test_tampered_ec_signature_raises_value_error(self) -> None:
        """An EC CSR with a corrupted signature raises ValueError."""
        ctx = RestCertificateRequestContext()
        csr = _make_ec_csr()
        mock_csr = Mock(spec=x509.CertificateSigningRequest)
        mock_csr.signature_hash_algorithm = hashes.SHA256()
        mock_csr.public_key.return_value = csr.public_key()
        mock_csr.signature = b'\x00' * 72  # wrong signature bytes
        mock_csr.tbs_certrequest_bytes = csr.tbs_certrequest_bytes
        ctx.cert_requested = mock_csr
        with pytest.raises(ValueError, match='Failed to verify the CSR signature'):
            RestCsrSignatureVerification().parse(ctx)

    def test_tampered_rsa_signature_raises_value_error(self) -> None:
        """An RSA CSR with a corrupted signature raises ValueError."""
        ctx = RestCertificateRequestContext()
        csr = _make_rsa_csr()
        mock_csr = Mock(spec=x509.CertificateSigningRequest)
        mock_csr.signature_hash_algorithm = hashes.SHA256()
        mock_csr.public_key.return_value = csr.public_key()
        mock_csr.signature = b'\x00' * 256  # wrong signature bytes
        mock_csr.tbs_certrequest_bytes = csr.tbs_certrequest_bytes
        ctx.cert_requested = mock_csr
        with pytest.raises(ValueError, match='Failed to verify the CSR signature'):
            RestCsrSignatureVerification().parse(ctx)


# ---------------------------------------------------------------------------
# RestMessageParser (composite)
# ---------------------------------------------------------------------------


class TestRestMessageParser:
    """Tests for RestMessageParser initialization and composition."""

    def test_has_five_components_in_correct_order(self) -> None:
        """RestMessageParser initializes with exactly 5 components in the documented order."""
        from request.message_parser.base import CertProfileParsing, DomainParsing
        parser = RestMessageParser()
        assert len(parser.components) == 5
        assert isinstance(parser.components[0], RestAuthorizationHeaderParsing)
        assert isinstance(parser.components[1], RestPkiMessageParsing)
        assert isinstance(parser.components[2], DomainParsing)
        assert isinstance(parser.components[3], CertProfileParsing)
        assert isinstance(parser.components[4], RestCsrSignatureVerification)

    def test_parse_delegates_to_all_components(self) -> None:
        """parse() invokes each component's parse method exactly once, in order."""
        parser = RestMessageParser()
        mock_ctx = Mock()
        with patch.object(parser.components[0], 'parse') as p0, \
             patch.object(parser.components[1], 'parse') as p1, \
             patch.object(parser.components[2], 'parse') as p2, \
             patch.object(parser.components[3], 'parse') as p3, \
             patch.object(parser.components[4], 'parse') as p4:
            parser.parse(mock_ctx)
        p0.assert_called_once_with(mock_ctx)
        p1.assert_called_once_with(mock_ctx)
        p2.assert_called_once_with(mock_ctx)
        p3.assert_called_once_with(mock_ctx)
        p4.assert_called_once_with(mock_ctx)

    def test_parse_stops_on_first_component_failure(self) -> None:
        """If the first component raises, subsequent components are not called."""
        parser = RestMessageParser()
        mock_ctx = Mock()
        with patch.object(parser.components[0], 'parse', side_effect=ValueError('auth failed')), \
             patch.object(parser.components[1], 'parse') as p1:
            with pytest.raises(ValueError, match='auth failed'):
                parser.parse(mock_ctx)
            p1.assert_not_called()
