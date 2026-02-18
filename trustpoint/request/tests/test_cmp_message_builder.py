"""Unit tests for the CMP message builder classes."""

from unittest.mock import Mock, patch

import pytest
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from pyasn1_modules import rfc4210, rfc4211

from request.message_builder.cmp import (
    CmpCertRequestBodyBuilding,
    CmpCertTemplateBuilding,
    CmpMessageBuilder,
    CmpMessageBuilderError,
    CmpPkiHeaderBuilding,
    CmpPkiMessageAssembly,
    _der_tlv,
)
from request.request_context import BaseRequestContext, CmpCertificateRequestContext
from trustpoint_core.oid import HmacAlgorithm


class TestCmpMessageBuilderError:
    """Test cases for CmpMessageBuilderError exception."""

    def test_exception_inheritance(self):
        """Test that CmpMessageBuilderError inherits from Exception."""
        assert issubclass(CmpMessageBuilderError, Exception)

    def test_exception_creation(self):
        """Test creating an instance of CmpMessageBuilderError."""
        error = CmpMessageBuilderError("Test error message")
        assert str(error) == "Test error message"


class TestDerTlv:
    """Test cases for the _der_tlv utility function."""

    def test_der_tlv_short_form(self):
        """Test DER TLV encoding with short form length."""
        tag_byte = 0xA4
        value = b"test_value"
        result = _der_tlv(tag_byte, value)

        # Tag byte + length byte + value
        expected = bytes([tag_byte, len(value)]) + value
        assert result == expected

    def test_der_tlv_long_form(self):
        """Test DER TLV encoding with long form length."""
        tag_byte = 0xA4
        # Create a value longer than 127 bytes to trigger long form
        value = b"x" * 200
        result = _der_tlv(tag_byte, value)

        # Tag byte + long form length encoding + value
        # 200 = 0xC8, which fits in one byte after the length indicator
        expected = bytes([tag_byte, 0x81, 0xC8]) + value  # 0x81 = long form, 1 byte for length
        assert result == expected


class TestCmpCertTemplateBuilding:
    """Test cases for CmpCertTemplateBuilding."""

    def test_build_success_minimal(self):
        """Test successful building with minimal required data."""
        builder = CmpCertTemplateBuilding()
        context = CmpCertificateRequestContext()

        # Create test data
        subject = x509.Name.from_rfc4514_string("CN=test.example.com")
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key = private_key.public_key()

        context.request_data = {
            'subject': subject,
            'public_key': public_key,
        }

        builder.build(context)

        # Verify the cert template was created
        assert '_cert_template' in context.validated_request_data
        cert_template = context.validated_request_data['_cert_template']
        assert isinstance(cert_template, rfc4211.CertTemplate)

    def test_build_wrong_context_type(self):
        """Test that building fails with wrong context type."""
        builder = CmpCertTemplateBuilding()
        context = BaseRequestContext()

        with pytest.raises(TypeError, match="CmpCertTemplateBuilding requires a CmpCertificateRequestContext"):
            builder.build(context)

    def test_build_missing_request_data(self):
        """Test that building fails when request_data is missing."""
        builder = CmpCertTemplateBuilding()
        context = CmpCertificateRequestContext()

        with pytest.raises(ValueError, match="request_data is missing from the context"):
            builder.build(context)

    def test_build_missing_subject(self):
        """Test that building fails when subject is missing."""
        builder = CmpCertTemplateBuilding()
        context = CmpCertificateRequestContext()

        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key = private_key.public_key()

        context.request_data = {
            'public_key': public_key,
        }

        with pytest.raises(ValueError, match="subject is required in request_data"):
            builder.build(context)

    def test_build_missing_public_key(self):
        """Test that building fails when public_key is missing."""
        builder = CmpCertTemplateBuilding()
        context = CmpCertificateRequestContext()

        subject = x509.Name.from_rfc4514_string("CN=test.example.com")

        context.request_data = {
            'subject': subject,
        }

        with pytest.raises(ValueError, match="public_key is required in request_data"):
            builder.build(context)

    def test_build_with_ec_key(self):
        """Test building with EC key."""
        builder = CmpCertTemplateBuilding()
        context = CmpCertificateRequestContext()

        # Create test data with EC key
        subject = x509.Name.from_rfc4514_string("CN=test.example.com")
        private_key = ec.generate_private_key(ec.SECP256R1())
        public_key = private_key.public_key()

        context.request_data = {
            'subject': subject,
            'public_key': public_key,
        }

        builder.build(context)

        # Verify the cert template was created
        assert '_cert_template' in context.validated_request_data
        cert_template = context.validated_request_data['_cert_template']
        assert isinstance(cert_template, rfc4211.CertTemplate)


class TestCmpCertRequestBodyBuilding:
    """Test cases for CmpCertRequestBodyBuilding."""

    @patch.object(CmpCertRequestBodyBuilding, '_build_pop_signature')
    @patch('request.message_builder.cmp.rfc4211.CertReqMsg')
    @patch('request.message_builder.cmp.rfc4211.CertRequest')
    @patch('request.message_builder.cmp.rfc4210.PKIBody')
    def test_build_success_cr_with_pop(self, mock_pki_body, mock_cert_request, mock_cert_req_msg, mock_build_pop):
        """Test successful building of CR with proof of possession."""
        mock_build_pop.return_value = Mock()
        
        builder = CmpCertRequestBodyBuilding()
        context = CmpCertificateRequestContext()

        # Set up prerequisite data (normally from CmpCertTemplateBuilding)
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        # Create a mock cert template
        cert_template = Mock()

        context.request_data = {
            'private_key': private_key,
            'use_initialization_request': False,  # CR
            'add_pop': True,
        }
        context.validated_request_data = {
            '_cert_template': cert_template,
        }

        builder.build(context)

        # Verify the PKI body was created
        assert '_pki_body' in context.validated_request_data
        pki_body = context.validated_request_data['_pki_body']
        assert isinstance(pki_body, Mock)  # Since we mocked PKIBody

    @patch.object(CmpCertRequestBodyBuilding, '_build_pop_signature')
    @patch('request.message_builder.cmp.rfc4211.CertReqMsg')
    @patch('request.message_builder.cmp.rfc4211.CertRequest')
    @patch('request.message_builder.cmp.rfc4210.PKIBody')
    def test_build_success_ir_without_pop(self, mock_pki_body, mock_cert_request, mock_cert_req_msg, mock_build_pop):
        """Test successful building of IR without proof of possession."""
        builder = CmpCertRequestBodyBuilding()
        context = CmpCertificateRequestContext()

        # Set up prerequisite data
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        # Create a mock cert template
        cert_template = Mock()

        context.request_data = {
            'private_key': private_key,
            'use_initialization_request': True,  # IR
            'add_pop': False,
        }
        context.validated_request_data = {
            '_cert_template': cert_template,
        }

        builder.build(context)

        # Verify the PKI body was created
        assert '_pki_body' in context.validated_request_data
        pki_body = context.validated_request_data['_pki_body']
        assert isinstance(pki_body, Mock)  # Since we mocked PKIBody

    def test_build_wrong_context_type(self):
        """Test that building fails with wrong context type."""
        builder = CmpCertRequestBodyBuilding()
        context = BaseRequestContext()

        with pytest.raises(TypeError, match="CmpCertRequestBodyBuilding requires a CmpCertificateRequestContext"):
            builder.build(context)

    def test_build_missing_cert_template(self):
        """Test that building fails when cert template is missing."""
        builder = CmpCertRequestBodyBuilding()
        context = CmpCertificateRequestContext()

        context.request_data = {}
        context.validated_request_data = {}

        with pytest.raises(ValueError, match="_cert_template is missing"):
            builder.build(context)

    def test_build_missing_private_key(self):
        """Test that building fails when private key is missing."""
        builder = CmpCertRequestBodyBuilding()
        context = CmpCertificateRequestContext()

        # Create a mock cert template
        cert_template = Mock()

        context.request_data = {}
        context.validated_request_data = {
            '_cert_template': cert_template,
        }

        with pytest.raises(ValueError, match="private_key is required in request_data"):
            builder.build(context)

    @patch.object(CmpCertRequestBodyBuilding, '_build_pop_signature')
    @patch('request.message_builder.cmp.rfc4211.CertReqMsg')
    @patch('request.message_builder.cmp.rfc4211.CertRequest')
    @patch('request.message_builder.cmp.rfc4210.PKIBody')
    def test_build_with_ec_key(self, mock_pki_body, mock_cert_request, mock_cert_req_msg, mock_build_pop):
        """Test building with EC private key."""
        mock_build_pop.return_value = Mock()
        
        builder = CmpCertRequestBodyBuilding()
        context = CmpCertificateRequestContext()

        # Set up prerequisite data with EC key
        private_key = ec.generate_private_key(ec.SECP256R1())

        # Create a mock cert template
        cert_template = Mock()

        context.request_data = {
            'private_key': private_key,
            'use_initialization_request': False,
            'add_pop': True,
        }
        context.validated_request_data = {
            '_cert_template': cert_template,
        }

        builder.build(context)

        # Verify the PKI body was created
        assert '_pki_body' in context.validated_request_data
        pki_body = context.validated_request_data['_pki_body']
        assert isinstance(pki_body, Mock)  # Since we mocked PKIBody

    # @patch.object(CmpCertRequestBodyBuilding, '_build_pop_signature')
    # def test_build_unsupported_key_type(self, mock_build_pop):
    #     """Test that building fails with unsupported key type."""
    #     # Make _build_pop_signature raise the unsupported key error
    #     mock_build_pop.side_effect = CmpMessageBuilderError("Unsupported private key type: <class 'unittest.mock.Mock'>")
    #
    #     builder = CmpCertRequestBodyBuilding()
    #     context = CmpCertificateRequestContext()
    #
    #     # Create a mock cert template
    #     cert_template = Mock()
    #
    #     # Mock an unsupported private key
    #     private_key = Mock()
    #     private_key.__class__ = Mock  # Make it not RSA or EC
    #
    #     context.request_data = {
    #         'private_key': private_key,
    #         'use_initialization_request': False,
    #         'add_pop': True,
    #     }
    #     context.validated_request_data = {
    #         '_cert_template': cert_template,
    #     }
    #
    #     with pytest.raises(CmpMessageBuilderError, match="Unsupported private key type"):
    #         builder.build(context)


class TestCmpPkiHeaderBuilding:
    """Test cases for CmpPkiHeaderBuilding."""

    def test_build_success_minimal(self):
        """Test successful header building with minimal required data."""
        builder = CmpPkiHeaderBuilding()
        context = CmpCertificateRequestContext()

        subject = x509.Name.from_rfc4514_string("CN=test.example.com")

        context.request_data = {
            'subject': subject,
            'recipient_name': "CN=CA.example.com",
        }

        builder.build(context)

        # Verify the PKI header was created
        assert '_pki_header' in context.validated_request_data
        pki_header = context.validated_request_data['_pki_header']
        assert isinstance(pki_header, rfc4210.PKIHeader)

    def test_build_success_with_sender_kid(self):
        """Test successful header building with sender KID."""
        builder = CmpPkiHeaderBuilding()
        context = CmpCertificateRequestContext()

        subject = x509.Name.from_rfc4514_string("CN=test.example.com")

        context.request_data = {
            'subject': subject,
            'recipient_name': "CN=CA.example.com",
            'sender_kid': 123,
        }

        builder.build(context)

        # Verify the PKI header was created
        assert '_pki_header' in context.validated_request_data
        pki_header = context.validated_request_data['_pki_header']
        assert isinstance(pki_header, rfc4210.PKIHeader)
        assert 'senderKID' in pki_header

    def test_build_success_with_protection(self):
        """Test successful header building with protection preparation."""
        builder = CmpPkiHeaderBuilding()
        context = CmpCertificateRequestContext()

        subject = x509.Name.from_rfc4514_string("CN=test.example.com")

        context.request_data = {
            'subject': subject,
            'recipient_name': "CN=CA.example.com",
            'prepare_shared_secret_protection': True,
            'hmac_algorithm': HmacAlgorithm.HMAC_SHA256,
        }

        builder.build(context)

        # Verify the PKI header was created with protection
        assert '_pki_header' in context.validated_request_data
        pki_header = context.validated_request_data['_pki_header']
        assert isinstance(pki_header, rfc4210.PKIHeader)
        assert 'protectionAlg' in pki_header

    def test_build_wrong_context_type(self):
        """Test that building fails with wrong context type."""
        builder = CmpPkiHeaderBuilding()
        context = BaseRequestContext()

        with pytest.raises(TypeError, match="CmpPkiHeaderBuilding requires a CmpCertificateRequestContext"):
            builder.build(context)

    def test_build_missing_subject(self):
        """Test that building fails when subject is missing."""
        builder = CmpPkiHeaderBuilding()
        context = CmpCertificateRequestContext()

        context.request_data = {
            'recipient_name': "CN=CA.example.com",
        }

        with pytest.raises(ValueError, match="subject is required in request_data"):
            builder.build(context)

    def test_build_missing_recipient_name(self):
        """Test that building fails when recipient_name is missing."""
        builder = CmpPkiHeaderBuilding()
        context = CmpCertificateRequestContext()

        subject = x509.Name.from_rfc4514_string("CN=test.example.com")

        context.request_data = {
            'subject': subject,
        }

        with pytest.raises(ValueError, match="recipient_name is required in request_data"):
            builder.build(context)


class TestCmpPkiMessageAssembly:
    """Test cases for CmpPkiMessageAssembly."""

    def test_build_success(self):
        """Test successful PKI message assembly."""
        builder = CmpPkiMessageAssembly()
        context = CmpCertificateRequestContext()

        # Create mock header and body
        header = rfc4210.PKIHeader()
        body = rfc4210.PKIBody()

        context.validated_request_data = {
            '_pki_header': header,
            '_pki_body': body,
        }

        builder.build(context)

        # Verify the PKI message was assembled
        assert context.parsed_message is not None
        assert isinstance(context.parsed_message, rfc4210.PKIMessage)

    def test_build_wrong_context_type(self):
        """Test that building fails with wrong context type."""
        builder = CmpPkiMessageAssembly()
        context = BaseRequestContext()

        with pytest.raises(TypeError, match="CmpPkiMessageAssembly requires a CmpCertificateRequestContext"):
            builder.build(context)

    def test_build_missing_header(self):
        """Test that building fails when header is missing."""
        builder = CmpPkiMessageAssembly()
        context = CmpCertificateRequestContext()

        body = rfc4210.PKIBody()

        context.validated_request_data = {
            '_pki_body': body,
        }

        with pytest.raises(ValueError, match="_pki_header is missing"):
            builder.build(context)

    def test_build_missing_body(self):
        """Test that building fails when body is missing."""
        builder = CmpPkiMessageAssembly()
        context = CmpCertificateRequestContext()

        header = rfc4210.PKIHeader()

        context.validated_request_data = {
            '_pki_header': header,
        }

        with pytest.raises(ValueError, match="_pki_body is missing"):
            builder.build(context)


class TestCmpMessageBuilder:
    """Test cases for CmpMessageBuilder composite."""

    def test_init(self):
        """Test initialization of CmpMessageBuilder."""
        builder = CmpMessageBuilder()

        # Should have 4 components
        assert len(builder.components) == 4
        assert isinstance(builder.components[0], CmpCertTemplateBuilding)
        assert isinstance(builder.components[1], CmpCertRequestBodyBuilding)
        assert isinstance(builder.components[2], CmpPkiHeaderBuilding)
        assert isinstance(builder.components[3], CmpPkiMessageAssembly)

    def test_build_success_minimal(self):
        """Test successful building with minimal required data."""
        builder = CmpMessageBuilder()
        context = CmpCertificateRequestContext()

        # Create test data
        subject = x509.Name.from_rfc4514_string("CN=test.example.com")
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key = private_key.public_key()

        context.request_data = {
            'subject': subject,
            'public_key': public_key,
            'private_key': private_key,
            'recipient_name': "CN=CA.example.com",
            'use_initialization_request': False,
            'add_pop': True,
        }

        builder.build(context)

        # Verify the final PKI message was created
        assert context.parsed_message is not None
        assert isinstance(context.parsed_message, rfc4210.PKIMessage)

    def test_build_fails_on_missing_data(self):
        """Test that building fails when required data is missing."""
        builder = CmpMessageBuilder()
        context = CmpCertificateRequestContext()

        # Missing most required data
        context.request_data = {}

        with pytest.raises(ValueError):
            builder.build(context)
