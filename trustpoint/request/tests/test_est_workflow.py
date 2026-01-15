import base64

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from django.test.client import RequestFactory
from pki.util.cert_profile import JSONProfileVerifier
from pki.util.cert_req_converter import JSONCertRequestConverter

from request.authentication import EstAuthentication
from request.authorization import CertificateProfileAuthorization, EstAuthorization, EstOperationAuthorization
from request.http_request_validator import EstHttpRequestValidator
from request.operation_processor import CertificateIssueProcessor
from request.pki_message_parser import EstMessageParser
from request.request_context import RequestContext
from trustpoint.logger import LoggerMixin


class TestESTHelper(LoggerMixin):

    def test_est_no_onboarding_username_password_auth(
            self,
            est_device_without_onboarding,
            rsa_private_key
    ) -> None:
        """Test client certificate validation when the request does not contain the 'HTTP_SSL_CLIENT_CERT' header."""
        device = est_device_without_onboarding['device']

        operation = 'simpleenroll'
        domain_str = device.domain.unique_name if device.domain else None
        if not domain_str:
            raise ValueError('Domain for the device cannot be None')

        est_username = device.est_username
        est_password = device.no_onboarding_config.est_password
        certtemplate_str = 'tls_server'
        operation_str = 'simpleenroll'
        common_name = device.common_name
        expected_domain = device.domain

        csr_builder = x509.CertificateSigningRequestBuilder().subject_name(
            x509.Name([
                x509.NameAttribute(x509.NameOID.COMMON_NAME, common_name),
            ])
        )

        csr = csr_builder.sign(private_key=rsa_private_key, algorithm=hashes.SHA256())

        protocol_str = 'est'

        # Prepare credentials for authorization header
        credentials = f'{est_username}:{est_password}'.encode()
        auth_header = base64.b64encode(credentials).decode('utf-8')

        # Generate HTTP request
        request_factory = RequestFactory()
        request = request_factory.post(
            path=f'/.well-known/{protocol_str}/{domain_str}/{certtemplate_str}/{operation}',
            data=csr.public_bytes(serialization.Encoding.DER),
            content_type='application/pkcs10',
            HTTP_AUTHORIZATION=f'Basic {auth_header}',
        )

        mock_context = RequestContext(raw_message=request,
                                      domain_str=domain_str,
                                      protocol=protocol_str,
                                      operation=operation_str,
                                      cert_profile_str=certtemplate_str)

        validator = EstHttpRequestValidator()

        parser = EstMessageParser()
        est_authenticator = EstAuthentication()
        est_authorizer = EstAuthorization()
        est_authorizer.add(CertificateProfileAuthorization())
        est_authorizer.add(EstOperationAuthorization(['simpleenroll']))

        validator.validate(mock_context)

        assert mock_context.client_certificate is None
        assert mock_context.client_intermediate_certificate is None
        assert mock_context.est_username == device.est_username
        assert mock_context.est_password == device.no_onboarding_config.est_password

        parser.parse(mock_context)

        assert mock_context.cert_requested is not None
        assert isinstance(mock_context.cert_requested, x509.CertificateSigningRequest), \
            f'cert_requested must be of type CertificateSigningRequest, got {type(mock_context.cert_requested)}.'
        assert mock_context.domain == expected_domain, \
            f'Domain in context {mock_context.domain} does not match expected domain {expected_domain}'
        assert mock_context.est_encoding in {'pkcs7'}

        est_authenticator.authenticate(mock_context)

        assert mock_context.device is not None, 'Authentication failed: Device not found in context.'
        assert mock_context.device.common_name == device.common_name, \
            f'Authenticated device common_name {mock_context.device.common_name} does not match expected {device.common_name}.'

        est_authorizer.authorize(mock_context)

        assert True, 'Authorization passed as expected.'


    def test_est_with_onboarding_client_certificate_authentication(
            self,
            domain_credential_est_onboarding,
            rsa_private_key
    ) -> None:
        """Test EST client certificate authentication for a device WITH onboarding."""
        device = domain_credential_est_onboarding.get('device')
        domain_credential = domain_credential_est_onboarding.get('domain_credential')

        certtemplate_str = 'tls_server'
        operation_str = 'simpleenroll'
        protocol_str = 'est'
        domain_str = device.domain.unique_name

        csr_builder = x509.CertificateSigningRequestBuilder().subject_name(
            x509.Name([
                x509.NameAttribute(x509.NameOID.COMMON_NAME, 'Test TLS Client Certificate'),
            ])
        )
        csr = csr_builder.sign(private_key=rsa_private_key, algorithm=hashes.SHA256())

        request_factory = RequestFactory()
        cert_pem = domain_credential.credential.certificate.cert_pem

        request = request_factory.post(
            path=f'/.well-known/{protocol_str}/{domain_str}/{certtemplate_str}/{operation_str}',
            data=csr.public_bytes(serialization.Encoding.DER),
            content_type='application/pkcs10',
            HTTP_SSL_CLIENT_CERT=cert_pem,
        )

        # Build mock context
        mock_context = RequestContext(
            raw_message=request,
            domain_str=domain_str,
            protocol=protocol_str,
            operation=operation_str,
            cert_profile_str=certtemplate_str,
        )

        validator = EstHttpRequestValidator()
        parser = EstMessageParser()
        authenticator = EstAuthentication()
        authorizer = EstAuthorization()
        authorizer.add(CertificateProfileAuthorization())
        authorizer.add(EstOperationAuthorization([operation_str]))

        # Run request validation
        validator.validate(mock_context)

        assert mock_context.client_certificate is not None, 'Client certificate not parsed'

        expected_certificate = domain_credential.credential.get_certificate()

        client_cert_cn = mock_context.client_certificate.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[
            0].value
        expected_cert_cn = expected_certificate.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value

        assert client_cert_cn == expected_cert_cn, \
            f"Client certificate common name '{client_cert_cn}' does not match expected '{expected_cert_cn}'"

        # Parse request
        parser.parse(mock_context)

        assert mock_context.cert_requested is not None
        assert isinstance(mock_context.cert_requested, x509.CertificateSigningRequest), \
            'Request CSR is invalid'
        assert mock_context.domain == device.domain, \
            'Domain in context does not match expected domain'

        # Authenticate
        authenticator.authenticate(mock_context)

        assert mock_context.device is not None, 'Authentication failed, device not linked'
        assert mock_context.device.common_name == device.common_name, \
            'Authenticated device common name does not match expected'

        # Authorization
        authorizer.authorize(mock_context)

        assert True, 'Authorization passed as expected'

        # Certificate profile validation
        cert_request_json = JSONCertRequestConverter.to_json(mock_context.cert_requested)
        self.logger.info('Cert Request JSON: %s', cert_request_json)

        validated_req = JSONProfileVerifier.validate_request(cert_request_json)

        assert validated_req['subject']['common_name'] == 'Test TLS Client Certificate'

        mock_profile = {
            'type': 'cert_profile',
            'subj': {'allow':'*'},
            'ext': {
                'crl': {'uris': ['http://localhost/crl/2']},
            },
            'validity': {
                'days': 30
            }
        }

        validated_request = JSONProfileVerifier(mock_profile).apply_profile_to_request(validated_req)
        self.logger.info('Validated Cert Request JSON: %s', validated_request)

        mock_context.cert_requested_profile_validated = JSONCertRequestConverter.from_json(validated_request)
        CertificateIssueProcessor().process_operation(mock_context)
