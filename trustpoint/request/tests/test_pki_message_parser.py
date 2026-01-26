"""Unit tests for PKI message parser components."""
from unittest.mock import MagicMock, Mock, patch

import base64
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from pki.models import DomainModel

from request.message_parser import CmpMessageParser, EstMessageParser
from request.message_parser.base import CertProfileParsing, CompositeParsing, DomainParsing
from request.message_parser.cmp import CmpPkiMessageParsing
from request.message_parser.est import EstAuthorizationHeaderParsing, EstCsrSignatureVerification, EstPkiMessageParsing
from request.request_context import BaseCertificateRequestContext, BaseRequestContext, BaseRevocationRequestContext, CmpBaseRequestContext, EstBaseRequestContext, EstCertificateRequestContext


class TestEstPkiMessageParsing:
    """Test cases for EstPkiMessageParsing component."""

    def test_parse_pem_csr_success(self, test_csr_fixture):
        """Test parsing a valid PEM-encoded CSR."""
        mock_context = Mock(spec=EstCertificateRequestContext)
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
        mock_context = Mock(spec=EstCertificateRequestContext)
        mock_raw_message = Mock()
        mock_raw_message.body = test_csr_fixture.get_base64_der_with_newlines()
        mock_context.raw_message = mock_raw_message

        parser = EstPkiMessageParsing()
        parser.parse(mock_context)

        assert mock_context.cert_requested is not None
        assert mock_context.est_encoding == 'pkcs7'
        assert isinstance(mock_context.cert_requested, x509.CertificateSigningRequest)

    def test_parse_base64_der_csr_success(self, test_csr_fixture):
        """Test parsing a valid Base64-encoded DER CSR."""
        mock_context = Mock(spec=EstCertificateRequestContext)
        mock_raw_message = Mock()
        mock_raw_message.body = test_csr_fixture.get_base64_der()
        mock_context.raw_message = mock_raw_message

        parser = EstPkiMessageParsing()
        parser.parse(mock_context)

        assert mock_context.cert_requested is not None
        assert mock_context.est_encoding == 'pkcs7'
        assert isinstance(mock_context.cert_requested, x509.CertificateSigningRequest)

    def test_parse_der_csr_success(self, test_csr_fixture):
        """Test parsing a valid raw DER CSR."""
        mock_context = Mock(spec=EstCertificateRequestContext)
        mock_raw_message = Mock()
        mock_raw_message.body = test_csr_fixture.get_der()
        mock_context.raw_message = mock_raw_message

        parser = EstPkiMessageParsing()
        parser.parse(mock_context)

        assert mock_context.cert_requested is not None
        assert mock_context.est_encoding == 'pkcs7'
        assert isinstance(mock_context.cert_requested, x509.CertificateSigningRequest)

    def test_parse_missing_raw_message(self):
        """Test parsing with missing raw message."""
        mock_context = Mock(spec=EstCertificateRequestContext)
        mock_context.raw_message = None

        parser = EstPkiMessageParsing()

        try:
            parser.parse(mock_context)
            assert False, 'Expected ValueError to be raised'
        except ValueError as e:
            assert 'Raw message is missing from the context.' in str(e)

    def test_parse_missing_message_body(self):
        """Test parsing with missing message body."""
        mock_context = Mock(spec=EstCertificateRequestContext)
        mock_raw_message = Mock()
        mock_raw_message.body = None
        mock_context.raw_message = mock_raw_message

        parser = EstPkiMessageParsing()

        try:
            parser.parse(mock_context)
            assert False, 'Expected ValueError to be raised'
        except ValueError as e:
            assert 'Raw message is missing body.' in str(e)

    def test_parse_unsupported_format(self):
        """Test parsing with unsupported CSR format."""
        mock_context = Mock(spec=EstCertificateRequestContext)
        mock_raw_message = Mock()
        mock_raw_message.body = b'This is not valid base64 data!'
        mock_context.raw_message = mock_raw_message

        parser = EstPkiMessageParsing()

        try:
            parser.parse(mock_context)
            assert False, 'Expected ValueError to be raised'
        except ValueError as e:
            assert 'Failed to parse the CSR.' in str(e)

    def test_parse_exception_handling(self):
        """Test handling of parsing exceptions."""
        mock_context = Mock(spec=EstCertificateRequestContext)
        mock_raw_message = Mock()
        mock_raw_message.body = b'-----BEGIN CERTIFICATE REQUEST-----\ntest\n-----END CERTIFICATE REQUEST-----'
        mock_context.raw_message = mock_raw_message

        parser = EstPkiMessageParsing()

        with patch('request.message_parser.est.x509.load_pem_x509_csr', side_effect=Exception('Parse error')):
            try:
                parser.parse(mock_context)
                assert False, 'Expected ValueError to be raised'
            except ValueError as e:
                assert 'Failed to parse the CSR.' in str(e)



class TestEstCsrSignatureVerification:
    """Test cases for EstCsrSignatureVerification component."""

    def test_verify_rsa_signature_success(self, test_csr_fixture):
        """Test successful RSA signature verification."""
        mock_context = Mock(spec=EstCertificateRequestContext)
        mock_context.cert_requested = test_csr_fixture.get_cryptography_object()

        verifier = EstCsrSignatureVerification()

        verifier.parse(mock_context)

    def test_verify_missing_csr(self):
        """Test verification with missing CSR."""
        mock_context = Mock(spec=EstCertificateRequestContext)
        mock_context.cert_requested = None

        verifier = EstCsrSignatureVerification()

        try:
            verifier.parse(mock_context)
            assert False, 'Expected ValueError to be raised'
        except ValueError as e:
            assert 'CSR not found in the parsing context.' in str(e)

    def test_verify_missing_hash_algorithm(self):
        """Test verification with missing hash algorithm."""
        mock_context = Mock(spec=EstCertificateRequestContext)
        mock_csr = Mock(spec=x509.CertificateSigningRequest)
        mock_csr.signature_hash_algorithm = None
        mock_context.cert_requested = mock_csr

        verifier = EstCsrSignatureVerification()

        try:
            verifier.parse(mock_context)
            assert False, 'Expected ValueError to be raised'
        except ValueError as e:
            assert 'CSR does not contain a signature hash algorithm.' in str(e)

    def test_verify_unsupported_key_type(self):
        """Test verification with unsupported key type."""
        mock_context = Mock(spec=EstCertificateRequestContext)
        mock_csr = Mock(spec=x509.CertificateSigningRequest)
        mock_unsupported_key = Mock()
        mock_hash_algorithm = Mock(spec=hashes.SHA256)

        mock_csr.public_key.return_value = mock_unsupported_key
        mock_csr.signature_hash_algorithm = mock_hash_algorithm
        mock_context.cert_requested = mock_csr

        verifier = EstCsrSignatureVerification()

        try:
            verifier.parse(mock_context)
            assert False, 'Expected TypeError to be raised'
        except TypeError as e:
            assert 'Unsupported public key type for CSR signature verification.' in str(e)

    def test_verify_signature_failure(self):
        """Test handling of signature verification failure."""
        mock_context = Mock(spec=EstCertificateRequestContext)
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

        with patch('request.message_parser.est.padding.PKCS1v15'):
            try:
                verifier.parse(mock_context)
                assert False, 'Expected ValueError to be raised'
            except ValueError as e:
                assert 'Failed to verify the CSR signature.' in str(e)


class TestEstAuthorizationHeaderParsing:
    """Test EstAuthorizationHeaderParsing class."""

    def test_validate_success(self):
        """Test successful validation and credential extraction."""
        validator = EstAuthorizationHeaderParsing()
        context = EstBaseRequestContext()
        context.raw_message = MagicMock()

        # Create valid Basic auth header
        credentials = 'username:password'
        encoded_credentials = base64.b64encode(credentials.encode()).decode()
        context.raw_message.headers = {'Authorization': f'Basic {encoded_credentials}'}

        validator.parse(context)
        assert context.est_username == 'username'
        assert context.est_password == 'password'

    def test_validate_missing_authorization(self):
        """Test that missing Authorization header passes."""
        validator = EstAuthorizationHeaderParsing()
        context = EstBaseRequestContext()
        context.raw_message = MagicMock()
        context.raw_message.headers = {'Other-Header': 'value'}

        # Should not raise any exception
        validator.parse(context)

    def test_validate_non_basic_auth(self):
        """Test that non-Basic auth does not pass."""
        validator = EstAuthorizationHeaderParsing()
        context = EstBaseRequestContext()
        context.raw_message = MagicMock()
        context.raw_message.headers = {'Authorization': 'Bearer token123'}

        try:
            validator.parse(context)
            assert False, 'Expected ValueError to be raised'
        except ValueError as e:
            assert "Authorization header must start with 'Basic'." in str(e)

    def test_validate_malformed_basic_auth(self):
        """Test ValueError for malformed Basic auth credentials."""
        validator = EstAuthorizationHeaderParsing()
        context = EstBaseRequestContext()
        context.raw_message = MagicMock()
        context.raw_message.headers = {'Authorization': 'Basic invalid_base64!!!'}

        try:
            validator.parse(context)
            assert False, 'Expected ValueError to be raised'
        except ValueError as e:
            assert "Malformed 'Authorization' header credentials" in str(e)

    def test_validate_basic_auth_no_colon(self):
        """Test ValueError for Basic auth without colon separator."""
        validator = EstAuthorizationHeaderParsing()
        context = EstBaseRequestContext()
        context.raw_message = MagicMock()

        # Valid base64 but no colon separator
        credentials = 'usernamepassword'
        encoded_credentials = base64.b64encode(credentials.encode()).decode()
        context.raw_message.headers = {'Authorization': f'Basic {encoded_credentials}'}

        try:
            validator.parse(context)
            assert False, 'Expected ValueError to be raised'
        except ValueError as e:
            assert "Malformed 'Authorization' header credentials" in str(e)

    def test_validate_missing_raw_message(self):
        """Test ValueError when raw_message is None."""
        validator = EstAuthorizationHeaderParsing()
        context = EstBaseRequestContext()
        context.raw_message = None

        try:
            validator.parse(context)
            assert False, 'Expected ValueError to be raised'
        except ValueError as e:
            assert 'Raw message is missing from the context' in str(e)

    def test_validate_missing_headers(self):
        """Test ValueError when headers are missing."""
        validator = EstAuthorizationHeaderParsing()
        context = EstBaseRequestContext()
        context.raw_message = MagicMock()
        context.raw_message.headers = None

        try:
            validator.parse(context)
            assert False, 'Expected ValueError to be raised'
        except ValueError as e:
            assert 'Raw message is missing headers' in str(e)


class TestDomainParsing:
    """Test cases for DomainParsing component."""

    def test_parse_domain_success(self):
        """Test successful domain parsing."""
        mock_context = Mock(spec=BaseRequestContext)
        mock_context.domain_str = 'test.domain.com'
        mock_domain = Mock(spec=DomainModel)

        parser = DomainParsing()

        with patch.object(parser, '_extract_requested_domain', return_value=(mock_domain)):
            parser.parse(mock_context)

        assert mock_context.domain == mock_domain

    def test_parse_missing_domain(self):
        """Test parsing with missing domain string.

        It is not mandatory to have a domain at this stage (e.g. general endpoint without path segment).
        Domain can be resolved from device in authentication step.
        """
        mock_context = Mock(spec=BaseRequestContext)
        mock_context.domain_str = None

        parser = DomainParsing()
        parser.parse(mock_context)

    def test_parse_domain_validation_error(self):
        """Test domain validation error handling."""
        mock_context = Mock(spec=BaseRequestContext)
        mock_context.domain_str = 'invalid.domain.com'

        parser = DomainParsing()

        with patch.object(parser, '_extract_requested_domain', side_effect=ValueError('Domain not found')):
            with pytest.raises(ValueError, match='Domain not found'):
                parser.parse(mock_context)

    def test_parse_domain_not_found(self):
        """Test domain not found error handling."""
        mock_context = Mock(spec=BaseRequestContext)
        mock_context.domain_str = 'missing.domain.com'

        parser = DomainParsing()

        with patch.object(parser, '_extract_requested_domain',
                          side_effect=ValueError("Domain 'missing.domain.com' does not exist.")):
            try:
                parser.parse(mock_context)
                assert False, 'Expected ValueError to be raised'
            except ValueError as e:
                assert "Domain 'missing.domain.com' does not exist." in str(e)

    def test_extract_requested_domain_success(self):
        """Test successful domain extraction."""
        mock_domain = Mock(spec=DomainModel)

        parser = DomainParsing()

        with patch.object(DomainModel.objects, 'get', return_value=mock_domain):
            domain = parser._extract_requested_domain('test.domain.com')

        assert domain == mock_domain

    def test_extract_requested_domain_not_exist(self):
        """Test domain extraction when domain doesn't exist."""
        parser = DomainParsing()

        with patch.object(DomainModel.objects, 'get', side_effect=DomainModel.DoesNotExist):
            with pytest.raises(ValueError, match="Domain 'nonexistent.domain.com' does not exist."):
                parser._extract_requested_domain('nonexistent.domain.com')

    def test_extract_requested_domain_multiple_found(self):
        """Test domain extraction when multiple domains found."""
        parser = DomainParsing()

        with patch.object(DomainModel.objects, 'get', side_effect=DomainModel.MultipleObjectsReturned):
            with pytest.raises(ValueError, match="Multiple domains found for 'duplicate.domain.com'."):
                parser._extract_requested_domain('duplicate.domain.com')


class TestCertProfileParsing:
    """Test cases for CertProfileParsing component."""

    def test_parse_cert_profile_not_cert_request_context(self):
        """Test missing cert profile string is ignored if not a certificate request context."""
        mock_context = Mock(spec=BaseRevocationRequestContext)
        mock_context.cert_profile_str = None

        parser = CertProfileParsing()
        ret_value = parser.parse(mock_context)

        assert not ret_value


    def test_parse_cert_profile_str_success(self):
        """Test successful certificate profile string parsing."""
        mock_context = Mock(spec=BaseCertificateRequestContext)
        mock_context.cert_profile_str = 'test_template'

        parser = CertProfileParsing()
        parser.parse(mock_context)

        assert mock_context.cert_profile_str == 'test_template'

    def test_parse_missing_cert_profile_str(self):
        """Test parsing with missing certificate template."""
        mock_context = Mock(spec=BaseCertificateRequestContext)
        mock_context.cert_profile_str = None

        parser = CertProfileParsing()

        try:
            parser.parse(mock_context)
            assert False, 'Expected ValueError to be raised'
        except ValueError as e:
            assert 'Certificate profile is missing in the request context.' in str(e)


class TestCmpPkiMessageParsing:
    """Test cases for CmpPkiMessageParsing component."""

    def test_parse_cmp_message_success(self):
        """Test successful CMP message parsing."""
        mock_context = Mock(spec=CmpBaseRequestContext)
        mock_raw_message = Mock()
        mock_raw_message.body = b'cmp_message_data'
        mock_context.raw_message = mock_raw_message
        mock_pki_message = Mock()

        parser = CmpPkiMessageParsing()

        with patch('request.message_parser.cmp.ber_decoder.decode', return_value=(mock_pki_message, None)), \
             patch.object(parser, '_extract_signer_certificate'):
            parser.parse(mock_context)

        assert mock_context.parsed_message == mock_pki_message

    def test_parse_missing_raw_message(self):
        """Test parsing with missing raw message."""
        mock_context = Mock(spec=CmpBaseRequestContext)
        mock_context.raw_message = None

        parser = CmpPkiMessageParsing()

        try:
            parser.parse(mock_context)
            assert False, 'Expected ValueError to be raised'
        except ValueError as e:
            assert 'Raw message is missing from the context.' in str(e)

    def test_parse_missing_message_body(self):
        """Test parsing with missing message body."""
        mock_context = Mock(spec=CmpBaseRequestContext)
        mock_raw_message = Mock()
        mock_raw_message.body = None
        mock_context.raw_message = mock_raw_message

        parser = CmpPkiMessageParsing()

        try:
            parser.parse(mock_context)
            assert False, 'Expected ValueError to be raised'
        except ValueError as e:
            assert 'Raw message is missing body.' in str(e)

    def test_parse_decode_error(self):
        """Test handling of decode errors."""
        mock_context = Mock(spec=CmpBaseRequestContext)
        mock_raw_message = Mock()
        mock_raw_message.body = b'invalid_cmp_data'
        mock_context.raw_message = mock_raw_message

        parser = CmpPkiMessageParsing()

        with patch('request.message_parser.cmp.ber_decoder.decode', side_effect=ValueError('Decode error')):
            try:
                parser.parse(mock_context)
                assert False, 'Expected ValueError to be raised'
            except ValueError as e:
                assert 'Failed to parse the CMP message. It seems to be corrupted.' in str(e)

    def test_parse_type_error(self):
        """Test handling of type errors during decode."""
        mock_context = Mock(spec=CmpBaseRequestContext)
        mock_raw_message = Mock()
        mock_raw_message.body = b'invalid_cmp_data'
        mock_context.raw_message = mock_raw_message

        parser = CmpPkiMessageParsing()

        with patch('request.message_parser.cmp.ber_decoder.decode', side_effect=TypeError('Type error')):
            try:
                parser.parse(mock_context)
                assert False, 'Expected ValueError to be raised'
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

        assert len(parser.components) == 5
        assert isinstance(parser.components[0], CmpPkiMessageParsing)

    def test_parse_delegation(self):
        """Test that parse method delegates to components."""
        parser = CmpMessageParser()
        mock_context = Mock(spec=CmpBaseRequestContext)

        # Set up the mock context with required attributes for CMP parsing
        mock_context.raw_message = Mock()
        mock_context.raw_message.body = b'test_body'
        mock_context.parsed_message = None
        mock_context.operation = 'initialization'
        mock_context.cert_requested = None

        # Mock all component parse methods to avoid actual parsing
        for i, component in enumerate(parser.components):
            with patch.object(component, 'parse') as mock_parse:
                # Only call the first component to avoid cascading failures
                if i == 0:
                    parser.components = [component]  # Temporarily set only this component
                    parser.parse(mock_context)
                    mock_parse.assert_called_once_with(mock_context)
                    break


class TestEstMessageParser:
    """Test cases for EstMessageParser."""

    def test_initialization(self):
        """Test EstMessageParser initialization."""
        parser = EstMessageParser()

        assert len(parser.components) == 5
        assert isinstance(parser.components[0], EstAuthorizationHeaderParsing)
        assert isinstance(parser.components[1], EstPkiMessageParsing)
        assert isinstance(parser.components[2], DomainParsing)
        assert isinstance(parser.components[3], CertProfileParsing)
        assert isinstance(parser.components[4], EstCsrSignatureVerification)

    def test_parse_delegation(self):
        """Test that parse method delegates to all components."""
        parser = EstMessageParser()
        mock_context = Mock(spec=EstCertificateRequestContext)

        with patch.object(parser.components[0], 'parse') as mock_parse1, \
             patch.object(parser.components[1], 'parse') as mock_parse2, \
             patch.object(parser.components[2], 'parse') as mock_parse3, \
             patch.object(parser.components[3], 'parse') as mock_parse4, \
             patch.object(parser.components[4], 'parse') as mock_parse5:
            parser.parse(mock_context)

            mock_parse1.assert_called_once_with(mock_context)
            mock_parse2.assert_called_once_with(mock_context)
            mock_parse3.assert_called_once_with(mock_context)
            mock_parse4.assert_called_once_with(mock_context)
            mock_parse5.assert_called_once_with(mock_context)

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
                assert False, 'Expected ValueError to be raised'
            except ValueError as e:
                assert 'Test error' in str(e)

            mock_parse1.assert_called_once_with(mock_context)
            mock_parse2.assert_called_once_with(mock_context)
            mock_parse3.assert_not_called()
            mock_parse4.assert_not_called()
