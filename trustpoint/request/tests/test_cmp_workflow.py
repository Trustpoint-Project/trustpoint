
from cryptography import x509

from request.authentication import CmpAuthentication
from request.authorization import CmpAuthorization
from request.pki_message_parser import CmpMessageParser
from request.tests.openssl_cmp_factory import CompositeCMPCommand, BasicCMPArgs, ServerConfig, SharedSecretAuth, \
    CertificateRequest
from request.tests.openssl_keygen_factory import CompositeKeyGenerator, RSAKeyGenerator, KeyFileOutput
from request.http_request_validator import CmpHttpRequestValidator
from request.request_context import RequestContext
from request.tests.cmp_mock_server import CMPMockServer
from trustpoint.logger import LoggerMixin


class TestCMPHelper(LoggerMixin):
    def test_cmp_no_onboarding_shared_secret_auth(self, cmp_device_without_onboarding) -> None:
        """Test client certificate validation when the request does not contain the 'SSL_CLIENT_CERT' header."""

        device = cmp_device_without_onboarding.get("device")

        domain_str = device.domain.unique_name
        protocol_str = 'cmp'
        operation_str_long = 'certification'
        operation_str_short = 'cr'
        certtemplate_str = 'tls-server'

        cmp_factory = (CompositeCMPCommand("test_cmp", "Test CMP command")
        .add_component(BasicCMPArgs(cmd=operation_str_short))
        .add_component(ServerConfig(
            f"http://localhost:8443/.well-known/{protocol_str}/{operation_str_long}/{domain_str}/{certtemplate_str}/"))
        .add_component(SharedSecretAuth(f"{device.id}", f"pass:{device.cmp_shared_secret}"))
        .add_component(
            CertificateRequest("/CN=Trustpoint-TlsServer-Credential/O=TestOrg/OU=TestOrgUnit",
                               10,
                               "critical 127.0.0.1 ::1 localhost",
                               "1.3.6.1.5.5.7.3.1,1.3.6.1.5.5.7.3.2"  # serverAuth, clientAuth
                               )))

        keygen_factory = (CompositeKeyGenerator("RSA")
                          .add_component(RSAKeyGenerator(4096))
                          .add_component(KeyFileOutput()))

        mock_server = CMPMockServer(cmp_factory, keygen_factory, 'localhost', 8443)

        request, cmp_message, path, headers, content_length = mock_server.run_test()

        mock_server.stop_server()

        mock_context = RequestContext(raw_message=request,
                                      domain_str=domain_str,
                                      protocol=protocol_str,
                                      operation=operation_str_long,
                                      certificate_template=certtemplate_str)

        validator = CmpHttpRequestValidator()
        parser = CmpMessageParser()
        authenticator = CmpAuthentication()
        authorizer = CmpAuthorization(['tls-server', 'tls-client'], ['certification'])

        validator.validate(mock_context)

        assert mock_context.client_certificate is None
        assert mock_context.client_intermediate_certificate is None

        parser.parse(mock_context)

        assert mock_context.cert_requested is not None
        assert isinstance(mock_context.cert_requested, x509.base.CertificateSigningRequestBuilder), \
            f"cert_requested must be of type x509.base.CertificateSigningRequestBuilder, got {type(mock_context.cert_requested)}."
        assert mock_context.domain == device.domain, \
            f"Domain in context {mock_context.domain} does not match expected domain {device.domain.unique_name}"

        authenticator.authenticate(mock_context)

        assert mock_context.device is not None, "Authentication failed: Device not found in context."
        assert mock_context.device.common_name == device.common_name, \
            f"Authenticated device common_name {mock_context.device.common_name} does not match expected {device.common_name}."
        assert mock_context.cmp_shared_secret == device.cmp_shared_secret

        authorizer.authorize(mock_context)

        assert True, "Authorization passed as expected."
