"""Views for EST (Enrollment over Secure Transport) handling authentication and certificate issuance."""

import base64
from typing import Any, cast

from django.http import HttpRequest, HttpResponse, HttpResponseBase
from django.utils.decorators import method_decorator
from django.views import View
from django.views.decorators.csrf import csrf_exempt
from pki.models.domain import DomainModel
from request.authentication import EstAuthentication
from request.authorization import CertificateTemplateAuthorization, EstAuthorization, EstOperationAuthorization
from request.http_request_validator import EstHttpRequestValidator
from request.message_responder import EstErrorMessageResponder, EstMessageResponder
from request.operation_processor import CertificateIssueProcessor
from request.pki_message_parser import EstMessageParser
from request.profile_validator import ProfileValidator
from request.request_context import RequestContext
from trustpoint.logger import LoggerMixin


class UsernamePasswordAuthenticationError(Exception):
    """Exception raised for username and password authentication failures."""

THRESHOLD_LOGGER: int = 400


class LoggedHttpResponse(HttpResponse, LoggerMixin):
    """Custom HttpResponse that logs and prints error messages automatically."""

    def __init__(self, content: str | bytes = b'', status: int | None = None, *args: Any, **kwargs: Any) -> None:
        """Initialize the LoggedHttpResponse instance.

        Args:
            content (Any): The content of the response.
            status (Optional[int], optional): The HTTP status code of the response. Defaults to None.
            *args (Any): Additional positional arguments passed to HttpResponse.
            **kwargs (Any): Additional keyword arguments passed to HttpResponse.
        """
        if status and status >= THRESHOLD_LOGGER:
            if isinstance(content, bytes):
                content = content.decode('utf-8')
            self.logger.error('EST - ERROR - %s - %s', status, content)
        else:
            self.logger.info('EST - SUCCESS - %s', status)

        super().__init__(content, *args, status=status, **kwargs)


class EstRequestedDomainExtractorMixin:
    """Mixin to extract the requested domain.

    This mixin sets:
      - self.requested_domain: The DomainModel instance based on the 'domain' parameter.
      - self.issuing_ca_certificate: The CA certificate for the requested domain.
      - self.signature_suite: The signature suite derived from the CA certificate.
    """

    requested_domain: DomainModel | None

    def extract_requested_domain(self, domain_name: str)  -> tuple[DomainModel | None, LoggedHttpResponse | None]:
        """Extracts the requested domain and sets the relevant certificate and signature suite.

        :return: The response from the parent class's dispatch method.
        """
        try:
            requested_domain = DomainModel.objects.get(unique_name=domain_name)
        except DomainModel.DoesNotExist:
            return None, LoggedHttpResponse('Domain does not exist.', status=404)
        else:
            return requested_domain, None


@method_decorator(csrf_exempt, name='dispatch')
class EstSimpleEnrollmentView(LoggerMixin, View):
    """Handles simple EST (Enrollment over Secure Transport) enrollment requests.

    This view processes certificate signing requests (CSRs), authenticates the client using
    either Mutual TLS or username/password, validates the device, and issues the requested certificate
    based on the certificate template specified in the request.
    """

    def post(self, request: HttpRequest, *args: Any, **kwargs: Any) -> LoggedHttpResponse:
        """Handle POST requests for simple enrollment."""
        self.logger.info('Request received: method=%s path=%s', request.method, request.path)
        del args

        # TODO: This should really be done by the message parser,
        # it also needs to handle the case where one or both are omitted
        try:
            domain_name = cast('str', kwargs.get('domain'))
            cert_template = cast('str', kwargs.get('certtemplate'))

            ctx = RequestContext(
                raw_message=request,
                protocol='est',
                operation='simpleenroll',
                domain_str=domain_name,
                certificate_template=cert_template,
            )
        except Exception:
            err_msg = 'Failed to set up request context.'
            self.logger.exception(err_msg)
            return LoggedHttpResponse(err_msg, status=500)

        try:
            validator = EstHttpRequestValidator()
            validator.validate(ctx)

            parser = EstMessageParser()
            parser.parse(ctx)

            est_authenticator = EstAuthentication()
            est_authenticator.authenticate(ctx)

            est_authorizer = EstAuthorization(
                # Allowed templates are TODO and might depend on authentication method
                allowed_templates=['tls-client','tls-server','domaincredential'],
                allowed_operations=['simpleenroll']
            )
            est_authorizer.authorize(ctx)

            ProfileValidator.validate(ctx)

            CertificateIssueProcessor().process_operation(ctx)

            EstMessageResponder.build_response(ctx)

        except Exception:
            self.logger.exception('Error processing EST simpleenroll request')
            EstErrorMessageResponder.build_response(ctx)

        return LoggedHttpResponse(
            content=ctx.http_response_content,
            status=ctx.http_response_status,
            content_type=ctx.http_response_content_type
        )


@method_decorator(csrf_exempt, name='dispatch')
class EstSimpleReEnrollmentView(LoggerMixin, View):
    """Handles simple EST (Enrollment over Secure Transport) reenrollment requests.

    This view processes certificate signing requests (CSRs), authenticates the client using
    either Mutual TLS or username/password, validates the device, and issues the requested certificate
    based on the certificate template specified in the request.
    """

    def post(self, request: HttpRequest, *args: Any, **kwargs: Any) -> LoggedHttpResponse:
        """Handle POST requests for simple reenrollment."""
        self.logger.info('Request received: method=%s path=%s', request.method, request.path)
        del args

        # TODO: This should really be done by the message parser,
        # it also needs to handle the case where one or both are omitted
        try:
            domain_name = cast('str', kwargs.get('domain'))
            cert_template = cast('str', kwargs.get('certtemplate'))

            ctx = RequestContext(
                raw_message=request,
                protocol='est',
                operation='simplereenroll',
                domain_str=domain_name,
                certificate_template=cert_template,
            )
        except Exception:
            err_msg = 'Failed to set up request context.'
            self.logger.exception(err_msg)
            return LoggedHttpResponse(err_msg, status=500)

        try:
            validator = EstHttpRequestValidator()
            validator.validate(ctx)

            parser = EstMessageParser()
            parser.parse(ctx)

            est_authenticator = EstAuthentication()
            est_authenticator.authenticate(ctx)

            est_authorizer = EstAuthorization(
                # Allowed templates are TODO and might depend on authentication method
                allowed_templates=['tls-client','tls-server','domaincredential'],
                allowed_operations=['simplereenroll']
            )
            est_authorizer.authorize(ctx)

            ProfileValidator.validate(ctx)

            CertificateIssueProcessor().process_operation(ctx)

            EstMessageResponder.build_response(ctx)

        except Exception:
            self.logger.exception('Error processing EST simplereenroll request')
            EstErrorMessageResponder.build_response(ctx)

        return LoggedHttpResponse(
            content=ctx.http_response_content,
            status=ctx.http_response_status,
            content_type=ctx.http_response_content_type
        )



@method_decorator(csrf_exempt, name='dispatch')
class EstCACertsView(EstRequestedDomainExtractorMixin, View, LoggerMixin):
    """View to handle the EST /cacerts endpoint.

    Returns the CA certificate chain in a (simplified) PKCS#7 MIME format.

    URL pattern should supply the 'domain' parameter (e.g., /cacerts/<domain>/)
    """

    def get(self, request: HttpRequest, *args: Any, **kwargs: Any) -> LoggedHttpResponse:
        """Handle GET requests for the /cacerts endpoint.

        This method retrieves the CA certificate chain and returns it in PKCS#7 MIME format.
        """
        self.logger.info('Request received: method=%s path=%s', request.method, request.path)
        del request, args
        requested_domain: DomainModel | None

        try:
            domain_name = cast('str', kwargs.get('domain'))
            requested_domain, http_response = self.extract_requested_domain(domain_name=domain_name)

            if not http_response and requested_domain:

                if not requested_domain.issuing_ca:
                    return LoggedHttpResponse('The requested domain has no issuing CA configured', status=500)

                ca_credential_serializer = requested_domain.issuing_ca.credential.get_credential_serializer()
                pkcs7_certs = ca_credential_serializer.get_full_chain_as_serializer().as_pkcs7_der()
                b64_pkcs7 = base64.b64encode(pkcs7_certs).decode()

                formatted_b64_pkcs7 = '\n'.join([b64_pkcs7[i:i + 64] for i in range(0, len(b64_pkcs7), 64)])

                http_response = LoggedHttpResponse(
                    formatted_b64_pkcs7.encode(),
                    status=200,
                    content_type='application/pkcs7-mime',
                    headers={'Content-Transfer-Encoding': 'base64'}
                )

                if 'Vary' in http_response:
                    del http_response['Vary']
                if 'Content-Language' in http_response:
                    del http_response['Content-Language']

            if not http_response:
                http_response = LoggedHttpResponse('Something went wrong during EST getcacerts.', status=500)

        except Exception as e:  # noqa:BLE001
            return LoggedHttpResponse(
                f'Error retrieving CA certificates: {e!s}', status=500
            )
        else:
            return http_response


@method_decorator(csrf_exempt, name='dispatch')
class EstCsrAttrsView(View, LoggerMixin):
    """View to handle the EST /csrattrs endpoint.

    This endpoint is not supported and returns 404 Not Found.
    """

    def get(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponseBase:
        """Handle GET requests for the /csrattrs endpoint."""
        self.logger.info('Request received: method=%s path=%s', request.method, request.path)
        del request, args, kwargs

        return LoggedHttpResponse(
            'csrattrs/ is not supported', status=404
        )
