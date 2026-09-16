# Copyright (c) 2025 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Unit tests for PKI message parser components."""
from unittest.mock import MagicMock, Mock, patch

import base64
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from pyasn1.codec.der.encoder import encode as der_encode
from pyasn1.type import univ
from pyasn1_modules import rfc2459, rfc2511, rfc4210, rfc4211, rfc5280
from pki.models import DomainModel

from request.message_parser import CmpMessageParser, EstMessageParser
from request.message_parser.base import CertProfileParsing, CompositeParsing, DomainParsing
from request.message_parser.cmp import (
    CmpBodyValidation,
    CmpCertificateBodyValidation,
    CmpCertConfBodyValidation,
    CmpHeaderValidation,
    CmpPollReqBodyValidation,
    CmpRevocationBodyValidation,
    CmpPkiMessageParsing,
)
from request.message_parser.est import EstAuthorizationHeaderParsing, EstCsrSignatureVerification, EstPkiMessageParsing
from request.message_parser.rfc9480 import CertStatus, PKIBody
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
        mock_context.domain = None

        parser = CertProfileParsing()

        try:
            parser.parse(mock_context)
            assert False, 'Expected ValueError to be raised'
        except ValueError as e:
            assert 'Certificate profile is missing in the request context.' in str(e)

    def test_parse_resolves_cert_profile_from_domain(self):
        """Test that cert profile is resolved from domain when not explicitly set."""
        mock_domain = Mock()
        mock_domain.get_domain_credential_profile_name.return_value = 'custom_domain_credential'

        mock_context = Mock(spec=BaseCertificateRequestContext)
        mock_context.cert_profile_str = None
        mock_context.domain = mock_domain

        parser = CertProfileParsing()
        parser.parse(mock_context)

        assert mock_context.cert_profile_str == 'custom_domain_credential'

    def test_parse_resolves_default_domain_credential_from_domain(self):
        """Test that cert profile defaults to 'domain_credential' when domain has no custom profile."""
        mock_domain = Mock()
        mock_domain.get_domain_credential_profile_name.return_value = 'domain_credential'

        mock_context = Mock(spec=BaseCertificateRequestContext)
        mock_context.cert_profile_str = None
        mock_context.domain = mock_domain

        parser = CertProfileParsing()
        parser.parse(mock_context)

        assert mock_context.cert_profile_str == 'domain_credential'


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


class TestCmpTypedBodyValidation:
    """Exercise CMP body validators with real pyasn1 structures."""

    @staticmethod
    def _body(name: str):
        body = PKIBody()
        body[name].setComponentByPosition(0)
        return body

    def test_certconf_requires_one_status_and_cert_req_id_zero(self):
        body = self._body('certConf')
        body['certConf'].clear()
        with pytest.raises(ValueError, match='exactly one CertStatus'):
            CmpCertConfBodyValidation().parse_certconf_body(Mock(), body)

        status = CertStatus()
        status['certHash'] = b'certificate-hash'
        status['certReqId'] = 1
        body['certConf'].clear()
        body['certConf'].append(status)
        with pytest.raises(ValueError, match='certReqId in certConf MUST be 0'):
            CmpCertConfBodyValidation().parse_certconf_body(Mock(), body)

    def test_certconf_rejection_status_and_hash_algorithm_are_parsed(self):
        body = self._body('certConf')
        status = CertStatus()
        status['certHash'] = b'certificate-hash'
        status['certReqId'] = 0
        status['statusInfo']['status'] = 2
        status['statusInfo']['statusString'].append('rejected')
        status['hashAlg']['algorithm'] = '2.16.840.1.101.3.4.2.1'
        body['certConf'].clear()
        body['certConf'].append(status)

        context = Mock()
        CmpCertConfBodyValidation().parse_certconf_body(context, body)

        assert context.cert_hash == b'certificate-hash'
        assert context.cert_conf_status == 2
        assert context.cert_conf_status_string == 'rejected'
        assert context.cert_hash_algorithm_oid == '2.16.840.1.101.3.4.2.1'

    def test_pollreq_rejects_nonzero_cert_req_id(self):
        body = self._body('pollReq')
        body['pollReq'][0]['certReqId'] = 3
        with pytest.raises(ValueError, match='certReqId MUST be 0'):
            CmpPollReqBodyValidation().parse_pollreq_body(Mock(), body)

    def test_revocation_body_extracts_serial_and_default_reason(self):
        body = self._body('rr')
        body['rr'][0]['certDetails']['serialNumber'] = 0xABCD
        context = Mock()
        CmpRevocationBodyValidation().parse_rr_body(context, body)
        assert context.cert_serial_number == 'ABCD'
        assert context.revocation_reason.name == 'unspecified'

    def test_header_validation_rejects_wrong_version_and_lengths(self):
        message = rfc4210.PKIMessage()
        message['header']['pvno'] = 99
        with pytest.raises(ValueError, match='pvno fail'):
            CmpHeaderValidation()._check_header(message)

        message['header']['pvno'] = 2
        message['header']['transactionID'] = b'short'
        with pytest.raises(ValueError, match='transactionID fail'):
            CmpHeaderValidation()._check_header(message)

    def test_body_validation_rejects_unsupported_body(self):
        context = Mock(spec=CmpBaseRequestContext)
        context.parsed_message = rfc4210.PKIMessage()
        context.parsed_message['body']['error'].setComponentByPosition(0)
        with pytest.raises(ValueError, match='Unsupported CMP body type'):
            CmpBodyValidation().parse(context)

    def test_cert_request_rejects_invalid_shape_and_template_version(self):
        validator = CmpCertificateBodyValidation()
        cert_req = rfc2511.CertReqMsg()
        cert_request = cert_req['certReq']
        cert_request['certReqId'] = 0
        with pytest.raises(ValueError, match='Public key missing'):
            validator._validate_cert_request(cert_request)

        cert_request['certReqId'] = 1
        with pytest.raises(ValueError, match='certReqId must be 0'):
            validator._validate_cert_request(cert_request)

        cert_request['certReqId'] = 0
        cert_request['certTemplate']['version'] = 3
        with pytest.raises(ValueError, match='Version must be 2'):
            validator._validate_cert_request(cert_request)

    def test_cert_template_extensions_parse_typed_values(self):
        validator = CmpCertificateBodyValidation()
        extensions = rfc2459.Extensions()
        san = rfc2459.SubjectAltName()
        san.append(rfc2459.GeneralName().setComponentByName('dNSName', 'device.example'))
        san.append(rfc2459.GeneralName().setComponentByName('iPAddress', b'\x7f\x00\x00\x01'))
        san.append(rfc2459.GeneralName().setComponentByName('uniformResourceIdentifier', 'urn:device'))
        san.append(rfc2459.GeneralName().setComponentByName('rfc822Name', 'device@example'))
        basic_constraints = rfc2459.BasicConstraints()
        basic_constraints['cA'] = True
        basic_constraints['pathLenConstraint'] = 2
        key_usage = rfc2459.KeyUsage('111000000')
        eku = rfc2459.ExtKeyUsageSyntax()
        eku.append('1.3.6.1.5.5.7.3.2')
        policies = rfc2459.CertificatePolicies()
        policies[0]['policyIdentifier'] = '1.2.3.4'
        values = [
            ('2.5.29.17', der_encode(san), False),
            ('2.5.29.19', der_encode(basic_constraints), True),
            ('2.5.29.15', der_encode(key_usage), True),
            ('2.5.29.37', der_encode(eku), False),
            ('2.5.29.14', der_encode(rfc2459.SubjectKeyIdentifier(b'\x01\x02')), False),
            ('2.5.29.32', der_encode(policies), False),
        ]
        for index, (oid, value, critical) in enumerate(values):
            extension = rfc2459.Extension()
            extension['extnID'] = oid
            if critical:
                extension['critical'] = True
            extension['extnValue'] = value
            extensions[index] = extension

        parsed = validator._parse_cert_template_extensions(extensions)
        assert [extension.oid for extension in parsed] == [x509.ObjectIdentifier(oid) for oid, _, _ in values]
        assert parsed[0].value.get_values_for_type(x509.DNSName) == ['device.example']
        assert parsed[1].value.ca is True
        assert parsed[2].critical is True
        assert parsed[3].value[0].dotted_string == '1.3.6.1.5.5.7.3.2'

    def test_cert_template_extension_rejects_unsupported_oid_and_policy_qualifier(self):
        validator = CmpCertificateBodyValidation()
        unsupported = rfc2459.Extension()
        unsupported['extnID'] = '1.2.3.4.5'
        unsupported['extnValue'] = b'ignored'
        with pytest.raises(NotImplementedError, match='not supported'):
            validator._parse_cert_template_extensions([unsupported])

        policies = rfc2459.CertificatePolicies()
        policies[0]['policyIdentifier'] = '1.2.3.4'
        policies[0]['policyQualifiers'][0]['policyQualifierId'] = '1.3.6.1.5.5.7.2.1'
        policies[0]['policyQualifiers'][0]['qualifier'] = der_encode(univ.ObjectIdentifier('1.2.3.4'))
        with pytest.raises(ValueError, match='Policy qualifiers are not supported'):
            validator._parse_certificate_policies(der_encode(policies), critical=False)

    def test_revocation_body_parses_reason_and_rejects_missing_details(self):
        body = self._body('rr')
        request = body['rr'][0]
        request['certDetails']['serialNumber'] = 0x10
        reason = rfc5280.CRLReason('keyCompromise')
        crl_extension = request['crlEntryDetails'].componentType.clone()
        crl_extension['extnID'] = '2.5.29.21'
        crl_extension['extnValue'] = der_encode(reason)
        request['crlEntryDetails'].append(crl_extension)
        context = Mock()
        CmpRevocationBodyValidation().parse_rr_body(context, body)
        assert context.revocation_reason == x509.ReasonFlags.unspecified

        request['certDetails']['serialNumber'] = univ.noValue
        with pytest.raises(ValueError, match='serialNumber must be present'):
            CmpRevocationBodyValidation().parse_rr_body(context, body)

    def test_certconf_acceptance_defaults_and_rejects_invalid_status_or_hash(self):
        body = self._body('certConf')
        status = CertStatus()
        status['certHash'] = b'hash'
        status['certReqId'] = 0
        body['certConf'].clear()
        body['certConf'].append(status)
        context = Mock()
        CmpCertConfBodyValidation().parse_certconf_body(context, body)
        assert context.cert_conf_status == 0
        assert context.cert_hash_algorithm_oid is None

        status['statusInfo']['status'] = 1
        with pytest.raises(ValueError, match='accepted.*rejection'):
            CmpCertConfBodyValidation().parse_certconf_body(context, body)

    def test_header_implicit_confirm_and_poll_length_branches(self):
        message = rfc4210.PKIMessage()
        message['header']['pvno'] = 2
        message['header']['transactionID'] = b'x' * 16
        message['header']['senderNonce'] = b'y' * 16
        message['body']['ir'].setComponentByPosition(0)
        entry = message['header']['generalInfo'].componentType.clone()
        entry['infoType'] = '1.3.6.1.5.5.7.4.13'
        entry['infoValue'] = univ.OctetString(b'bad')
        message['header']['generalInfo'].append(entry)
        with pytest.raises(ValueError, match='implicit confirm entry fail'):
            CmpHeaderValidation()._check_implicit_confirm(Mock(operation='initialization'), message)

        poll = self._body('pollReq')
        poll['pollReq'].clear()
        with pytest.raises(ValueError, match='exactly one'):
            CmpPollReqBodyValidation().parse_pollreq_body(Mock(), poll)


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
