"""Unit tests for PKI message parser components."""
import base64
import pytest
from unittest.mock import Mock, patch, MagicMock
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives import hashes
from django.http import HttpResponse
from pyasn1.codec.ber import decoder
from pyasn1_modules import rfc4210

from request.pki_message_parser import (
    EstPkiMessageParsing,
    EstCsrSignatureVerification,
    DomainParsing,
    CertTemplateParsing,
    CmpPkiMessageParsing,
    CompositeParsing,
    CmpMessageParser,
    EstMessageParser,
)
from request.request_context import RequestContext
from pki.models import DomainModel


class TestEstPkiMessageParsing:
    """Test cases for EstPkiMessageParsing component."""

    def test_parse_pem_csr_success(self, test_csr_fixture):
        """Test parsing a valid PEM-encoded CSR."""
        mock_context = Mock(spec=RequestContext)
        mock_raw_message = Mock()
        mock_raw_message.body = test_csr_fixture.get_pem()
        mock_context.raw_message = mock_raw_message

        parser = EstPkiMessageParsing()
        parser.parse(mock_context)

        assert mock_context.cert_requested is not None
        assert mock_context.est_encoding == 'pem'
        assert isinstance(mock_context.cert_requested, x509.CertificateSigningRequest)

    def test_parse_base64_der_with_newlines_success(self, test_csr_fixture):
        """Test parsing a valid Base64-encoded DER CSR with newlines."""
        mock_context = Mock(spec=RequestContext)
        mock_raw_message = Mock()
        mock_raw_message.body = test_csr_fixture.get_base64_der_with_newlines()
        mock_context.raw_message = mock_raw_message

        parser = EstPkiMessageParsing()
        parser.parse(mock_context)

        assert mock_context.cert_requested is not None
        assert mock_context.est_encoding == 'base64_der'
        assert isinstance(mock_context.cert_requested, x509.CertificateSigningRequest)

    def test_parse_base64_der_csr_success(self, test_csr_fixture):
        """Test parsing a valid Base64-encoded DER CSR."""
        mock_context = Mock(spec=RequestContext)
        mock_raw_message = Mock()
        mock_raw_message.body = test_csr_fixture.get_base64_der()
        mock_context.raw_message = mock_raw_message

        parser = EstPkiMessageParsing()
        parser.parse(mock_context)

        assert mock_context.cert_requested is not None
        assert mock_context.est_encoding == 'base64_der'
        assert isinstance(mock_context.cert_requested, x509.CertificateSigningRequest)

    def test_parse_der_csr_success(self, test_csr_fixture):
        """Test parsing a valid raw DER CSR."""
        mock_context = Mock(spec=RequestContext)
        mock_raw_message = Mock()
        mock_raw_message.body = test_csr_fixture.get_der()
        mock_context.raw_message = mock_raw_message

        parser = EstPkiMessageParsing()
        parser.parse(mock_context)

        assert mock_context.cert_requested is not None
        assert mock_context.est_encoding == 'der'
        assert isinstance(mock_context.cert_requested, x509.CertificateSigningRequest)

    def test_parse_missing_raw_message(self):
        """Test parsing with missing raw message."""
        mock_context = Mock(spec=RequestContext)
        mock_context.raw_message = None

        parser = EstPkiMessageParsing()

        try:
            parser.parse(mock_context)
            assert False, "Expected ValueError to be raised"
        except ValueError as e:
            assert 'Raw message is missing from the context.' in str(e)

    def test_parse_missing_message_body(self):
        """Test parsing with missing message body."""
        mock_context = Mock(spec=RequestContext)
        mock_raw_message = Mock()
        mock_raw_message.body = None
        mock_context.raw_message = mock_raw_message

        parser = EstPkiMessageParsing()

        try:
            parser.parse(mock_context)
            assert False, "Expected ValueError to be raised"
        except ValueError as e:
            assert 'Raw message is missing body.' in str(e)

    def test_parse_unsupported_format(self):
        """Test parsing with unsupported CSR format."""
        mock_context = Mock(spec=RequestContext)
        mock_raw_message = Mock()
        mock_raw_message.body = b'This is not valid base64 data!'
        mock_context.raw_message = mock_raw_message

        parser = EstPkiMessageParsing()

        try:
            parser.parse(mock_context)
            assert False, "Expected ValueError to be raised"
        except ValueError as e:
            assert "Failed to parse the CSR." in str(e)

    def test_parse_exception_handling(self):
        """Test handling of parsing exceptions."""
        mock_context = Mock(spec=RequestContext)
        mock_raw_message = Mock()
        mock_raw_message.body = b'-----BEGIN CERTIFICATE REQUEST-----\ntest\n-----END CERTIFICATE REQUEST-----'
        mock_context.raw_message = mock_raw_message

        parser = EstPkiMessageParsing()

        with patch('request.pki_message_parser.x509.load_pem_x509_csr', side_effect=Exception('Parse error')):
            try:
                parser.parse(mock_context)
                assert False, "Expected ValueError to be raised"
            except ValueError as e:
                assert 'Failed to parse the CSR.' in str(e)



class TestEstCsrSignatureVerification:
    """Test cases for EstCsrSignatureVerification component."""

    def test_verify_rsa_signature_success(self, test_csr_fixture):
        """Test successful RSA signature verification."""
        mock_context = Mock(spec=RequestContext)
        mock_context.cert_requested = test_csr_fixture.get_cryptography_object()

        verifier = EstCsrSignatureVerification()

        verifier.parse(mock_context)

    def test_verify_missing_csr(self):
        """Test verification with missing CSR."""
        mock_context = Mock(spec=RequestContext)
        mock_context.cert_requested = None

        verifier = EstCsrSignatureVerification()

        try:
            verifier.parse(mock_context)
            assert False, "Expected ValueError to be raised"
        except ValueError as e:
            assert 'CSR not found in the parsing context.' in str(e)

    def test_verify_missing_hash_algorithm(self):
        """Test verification with missing hash algorithm."""
        mock_context = Mock(spec=RequestContext)
        mock_csr = Mock(spec=x509.CertificateSigningRequest)
        mock_csr.signature_hash_algorithm = None
        mock_context.cert_requested = mock_csr

        verifier = EstCsrSignatureVerification()

        try:
            verifier.parse(mock_context)
            assert False, "Expected ValueError to be raised"
        except ValueError as e:
            assert 'CSR does not contain a signature hash algorithm.' in str(e)

    def test_verify_unsupported_key_type(self):
        """Test verification with unsupported key type."""
        mock_context = Mock(spec=RequestContext)
        mock_csr = Mock(spec=x509.CertificateSigningRequest)
        mock_unsupported_key = Mock()
        mock_hash_algorithm = Mock(spec=hashes.SHA256)

        mock_csr.public_key.return_value = mock_unsupported_key
        mock_csr.signature_hash_algorithm = mock_hash_algorithm
        mock_context.cert_requested = mock_csr

        verifier = EstCsrSignatureVerification()

        try:
            verifier.parse(mock_context)
            assert False, "Expected TypeError to be raised"
        except TypeError as e:
            assert 'Unsupported public key type for CSR signature verification.' in str(e)

    def test_verify_signature_failure(self):
        """Test handling of signature verification failure."""
        mock_context = Mock(spec=RequestContext)
        mock_csr = Mock(spec=x509.CertificateSigningRequest)
        mock_rsa_key = Mock(spec=rsa.RSAPublicKey)
        mock_hash_algorithm = Mock(spec=hashes.SHA256)

        mock_csr.public_key.return_value = mock_rsa_key
        mock_csr.signature_hash_algorithm = mock_hash_algorithm
        mock_csr.signature = b'signature'
        mock_csr.tbs_certrequest_bytes = b'tbs_data'
        mock_context.cert_requested = mock_csr

        mock_rsa_key.verify.side_effect = Exception('Verification failed')

        verifier = EstCsrSignatureVerification()

        with patch('request.pki_message_parser.padding.PKCS1v15'):
            try:
                verifier.parse(mock_context)
                assert False, "Expected ValueError to be raised"
            except ValueError as e:
                assert 'Failed to verify the CSR signature.' in str(e)


class TestDomainParsing:
    """Test cases for DomainParsing component."""

    def test_parse_domain_success(self):
        """Test successful domain parsing."""
        mock_context = Mock(spec=RequestContext)
        mock_context.domain_str = 'test.domain.com'
        mock_domain = Mock(spec=DomainModel)

        parser = DomainParsing()

        with patch.object(parser, '_extract_requested_domain', return_value=(mock_domain, None)):
            parser.parse(mock_context)

        assert mock_context.domain == mock_domain

    def test_parse_missing_domain(self):
        """Test parsing with missing domain string."""
        mock_context = Mock(spec=RequestContext)
        mock_context.domain_str = None

        parser = DomainParsing()

        try:
            parser.parse(mock_context)
            assert False, "Expected ValueError to be raised"
        except ValueError as e:
            assert 'Domain is missing in the request context.' in str(e)

    def test_parse_domain_validation_error(self):
        """Test domain validation error handling."""
        mock_context = Mock(spec=RequestContext)
        mock_context.domain_str = 'invalid.domain.com'
        mock_error_response = Mock(spec=HttpResponse)
        mock_error_response.content.decode.return_value = 'Domain not found'

        parser = DomainParsing()

        with patch.object(parser, '_extract_requested_domain', return_value=(None, mock_error_response)):
            try:
                parser.parse(mock_context)
                assert False, "Expected ValueError to be raised"
            except ValueError as e:
                assert 'Domain validation failed: Domain not found' in str(e)

    def test_parse_domain_not_found(self):
        """Test domain not found error handling."""
        mock_context = Mock(spec=RequestContext)
        mock_context.domain_str = 'missing.domain.com'

        parser = DomainParsing()

        with patch.object(parser, '_extract_requested_domain', return_value=(None, None)):
            try:
                parser.parse(mock_context)
                assert False, "Expected ValueError to be raised"
            except ValueError as e:
                assert 'Domain validation failed: Domain not found.' in str(e)

    def test_extract_requested_domain_success(self):
        """Test successful domain extraction."""
        mock_domain = Mock(spec=DomainModel)

        parser = DomainParsing()

        with patch.object(DomainModel.objects, 'get', return_value=mock_domain):
            domain, error = parser._extract_requested_domain('test.domain.com')

        assert domain == mock_domain
        assert error is None

    def test_extract_requested_domain_not_exist(self):
        """Test domain extraction when domain doesn't exist."""
        parser = DomainParsing()

        with patch.object(DomainModel.objects, 'get', side_effect=DomainModel.DoesNotExist):
            domain, error = parser._extract_requested_domain('nonexistent.domain.com')

        assert domain is None
        assert error is not None
        assert error.status_code == 404

    def test_extract_requested_domain_multiple_found(self):
        """Test domain extraction when multiple domains found."""
        parser = DomainParsing()

        with patch.object(DomainModel.objects, 'get', side_effect=DomainModel.MultipleObjectsReturned):
            domain, error = parser._extract_requested_domain('duplicate.domain.com')

        assert domain is None
        assert error is not None
        assert error.status_code == 400


class TestCertTemplateParsing:
    """Test cases for CertTemplateParsing component."""

    def test_parse_certificate_template_success(self):
        """Test successful certificate template parsing."""
        mock_context = Mock(spec=RequestContext)
        mock_context.certificate_template = 'test_template'

        parser = CertTemplateParsing()
        parser.parse(mock_context)

        assert mock_context.certificate_template == 'test_template'

    def test_parse_missing_certificate_template(self):
        """Test parsing with missing certificate template."""
        mock_context = Mock(spec=RequestContext)
        mock_context.certificate_template = None

        parser = CertTemplateParsing()

        try:
            parser.parse(mock_context)
            assert False, "Expected ValueError to be raised"
        except ValueError as e:
            assert 'Certificate template is missing in the request context.' in str(e)


class TestCmpPkiMessageParsing:
    """Test cases for CmpPkiMessageParsing component."""

    def test_parse_cmp_message_success(self):
        """Test successful CMP message parsing."""
        mock_context = Mock(spec=RequestContext)
        mock_raw_message = Mock()
        mock_raw_message.body = b'cmp_message_data'
        mock_context.raw_message = mock_raw_message
        mock_pki_message = Mock()

        parser = CmpPkiMessageParsing()

        with patch('request.pki_message_parser.decoder.decode', return_value=(mock_pki_message, None)):
            parser.parse(mock_context)

        assert mock_context.parsed_message == mock_pki_message

    def test_parse_missing_raw_message(self):
        """Test parsing with missing raw message."""
        mock_context = Mock(spec=RequestContext)
        mock_context.raw_message = None

        parser = CmpPkiMessageParsing()

        try:
            parser.parse(mock_context)
            assert False, "Expected ValueError to be raised"
        except ValueError as e:
            assert 'Raw message is missing from the context.' in str(e)

    def test_parse_missing_message_body(self):
        """Test parsing with missing message body."""
        mock_context = Mock(spec=RequestContext)
        mock_raw_message = Mock()
        mock_raw_message.body = None
        mock_context.raw_message = mock_raw_message

        parser = CmpPkiMessageParsing()

        try:
            parser.parse(mock_context)
            assert False, "Expected ValueError to be raised"
        except ValueError as e:
            assert 'Raw message is missing body.' in str(e)

    def test_parse_decode_error(self):
        """Test handling of decode errors."""
        mock_context = Mock(spec=RequestContext)
        mock_raw_message = Mock()
        mock_raw_message.body = b'invalid_cmp_data'
        mock_context.raw_message = mock_raw_message

        parser = CmpPkiMessageParsing()

        with patch('request.pki_message_parser.decoder.decode', side_effect=ValueError('Decode error')):
            try:
                parser.parse(mock_context)
                assert False, "Expected ValueError to be raised"
            except ValueError as e:
                assert 'Failed to parse the CMP message. It seems to be corrupted.' in str(e)

    def test_parse_type_error(self):
        """Test handling of type errors during decode."""
        mock_context = Mock(spec=RequestContext)
        mock_raw_message = Mock()
        mock_raw_message.body = b'invalid_cmp_data'
        mock_context.raw_message = mock_raw_message

        parser = CmpPkiMessageParsing()

        with patch('request.pki_message_parser.decoder.decode', side_effect=TypeError('Type error')):
            try:
                parser.parse(mock_context)
                assert False, "Expected ValueError to be raised"
            except ValueError as e:
                assert 'Failed to parse the CMP message. It seems to be corrupted.' in str(e)


class TestCompositeParsing:
    """Test cases for CompositeParsing component."""

    def test_add_component(self):
        """Test adding a component to the composite parser."""
        composite = CompositeParsing()
        component = Mock()

        composite.add(component)

        assert component in composite.components

    def test_remove_component(self):
        """Test removing a component from the composite parser."""
        composite = CompositeParsing()
        component = Mock()
        composite.add(component)

        composite.remove(component)

        assert component not in composite.components

    def test_parse_calls_all_components(self):
        """Test that parse calls all components in order."""
        composite = CompositeParsing()
        component1 = Mock()
        component2 = Mock()
        mock_context = Mock()

        composite.add(component1)
        composite.add(component2)

        composite.parse(mock_context)

        component1.parse.assert_called_once_with(mock_context)
        component2.parse.assert_called_once_with(mock_context)

    def test_parse_empty_components(self):
        """Test parsing with no components."""
        composite = CompositeParsing()
        mock_context = Mock()

        # Should not raise any exception
        composite.parse(mock_context)


class TestCmpMessageParser:
    """Test cases for CmpMessageParser."""

    def test_initialization(self):
        """Test CmpMessageParser initialization."""
        parser = CmpMessageParser()

        assert len(parser.components) == 1
        assert isinstance(parser.components[0], CmpPkiMessageParsing)

    def test_parse_delegation(self):
        """Test that parse method delegates to components."""
        parser = CmpMessageParser()
        mock_context = Mock()

        with patch.object(parser.components[0], 'parse') as mock_parse:
            parser.parse(mock_context)
            mock_parse.assert_called_once_with(mock_context)


class TestEstMessageParser:
    """Test cases for EstMessageParser."""

    def test_initialization(self):
        """Test EstMessageParser initialization."""
        parser = EstMessageParser()

        assert len(parser.components) == 4
        assert isinstance(parser.components[0], EstPkiMessageParsing)
        assert isinstance(parser.components[1], DomainParsing)
        assert isinstance(parser.components[2], CertTemplateParsing)
        assert isinstance(parser.components[3], EstCsrSignatureVerification)

    def test_parse_delegation(self):
        """Test that parse method delegates to all components."""
        parser = EstMessageParser()
        mock_context = Mock()

        with patch.object(parser.components[0], 'parse') as mock_parse1, \
                patch.object(parser.components[1], 'parse') as mock_parse2, \
                patch.object(parser.components[2], 'parse') as mock_parse3, \
                patch.object(parser.components[3], 'parse') as mock_parse4:
            parser.parse(mock_context)

            mock_parse1.assert_called_once_with(mock_context)
            mock_parse2.assert_called_once_with(mock_context)
            mock_parse3.assert_called_once_with(mock_context)
            mock_parse4.assert_called_once_with(mock_context)

    def test_parse_component_failure_stops_execution(self):
        """Test that component failure stops execution of subsequent components."""
        parser = EstMessageParser()
        mock_context = Mock()

        with patch.object(parser.components[0], 'parse') as mock_parse1, \
                patch.object(parser.components[1], 'parse', side_effect=ValueError('Test error')) as mock_parse2, \
                patch.object(parser.components[2], 'parse') as mock_parse3, \
                patch.object(parser.components[3], 'parse') as mock_parse4:
            try:
                parser.parse(mock_context)
                assert False, "Expected ValueError to be raised"
            except ValueError as e:
                assert 'Test error' in str(e)

            mock_parse1.assert_called_once_with(mock_context)
            mock_parse2.assert_called_once_with(mock_context)
            mock_parse3.assert_not_called()
            mock_parse4.assert_not_called()