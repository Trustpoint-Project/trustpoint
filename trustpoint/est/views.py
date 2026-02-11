"""Views for EST (Enrollment over Secure Transport) handling authentication and certificate issuance."""

import base64
from typing import TYPE_CHECKING, Any, cast

from django.http import HttpRequest, HttpResponse, HttpResponseBase
from django.utils.decorators import method_decorator
from django.views import View
from django.views.decorators.csrf import csrf_exempt

from request.operation_processor.general import OperationProcessor

if TYPE_CHECKING:
    from pki.models.credential import CredentialModel

from pki.models.domain import DomainModel
from request.authentication import EstAuthentication
from request.authorization import EstAuthorization
from request.message_parser import EstMessageParser
from request.message_responder import EstErrorMessageResponder, EstMessageResponder
from request.request_context import EstCertificateRequestContext
from request.request_validator.http_req import EstHttpRequestValidator
from request.workflow_handler import WorkflowHandler
from trustpoint.logger import LoggerMixin
from workflows.events import Events


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

    def extract_requested_domain(self, domain_name: str) -> tuple[DomainModel | None, LoggedHttpResponse | None]:
        """Extracts the requested domain and sets the relevant certificate and signature suite.

        :return: The response from the parent class's dispatch method.
        """
        try:
            requested_domain = DomainModel.objects.get(unique_name=domain_name)
        except DomainModel.DoesNotExist:
            return None, LoggedHttpResponse('Domain does not exist.', status=404)
        else:
            return requested_domain, None


class EstSimpleEnrollmentMixin(LoggerMixin):
    """Mixin providing common logic for EST simple enrollment operations."""

    EVENT = Events.est_simpleenroll

    def process_enrollment(
        self,
        request: HttpRequest,
        domain_name: str | None,
        cert_profile: str | None,
    ) -> HttpResponse:
        """Process an EST simple enrollment request.

        Args:
            request: The HTTP request object.
            domain_name: The domain name (can be None for default).
            cert_profile: The certificate profile name (can be None for default).

        Returns:
            LoggedHttpResponse with the enrollment result.
        """
        self.logger.info('Request received: method=%s path=%s', request.method, request.path)

        try:
            # TODO (FHK): Implement a more robust way to allow the issuance of Issuing CA certificates  # noqa: FIX002
            # Allow CA certificate requests if using the issuing_ca profile
            allow_ca_cert = cert_profile == 'issuing_ca'

            ctx = EstCertificateRequestContext(
                raw_message=request,
                protocol='est',
                operation='simpleenroll',
                domain_str=domain_name,
                cert_profile_str=cert_profile,
                allow_ca_certificate_request=allow_ca_cert,
                event=self.EVENT
            )

        except Exception:
            err_msg = 'Failed to set up EST request context.'
            self.logger.exception(err_msg)
            return HttpResponse(err_msg, status=500)

        try:
            validator = EstHttpRequestValidator()
            validator.validate(ctx)

            parser = EstMessageParser()
            ctx = cast('EstCertificateRequestContext', parser.parse(ctx))

            est_authenticator = EstAuthentication()
            est_authenticator.authenticate(ctx)

            est_authorizer = EstAuthorization(
                allowed_operations=['simpleenroll']
            )
            est_authorizer.authorize(ctx)

            WorkflowHandler().handle(ctx)

            OperationProcessor().process_operation(ctx)

            EstMessageResponder.build_response(ctx)

        except Exception:
            self.logger.exception('Error processing EST simpleenroll request')
            EstErrorMessageResponder.build_response(ctx)

        return ctx.to_http_response()


@method_decorator(csrf_exempt, name='dispatch')
class EstSimpleEnrollmentView(EstSimpleEnrollmentMixin, View):
    """Handles simple EST (Enrollment over Secure Transport) enrollment requests."""

    def post(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        """Handle POST requests for simple enrollment with domain and cert profile in URL."""
        del args

        domain_name = cast('str', kwargs.get('domain'))
        cert_profile = cast('str', kwargs.get('cert_profile', 'domain_credential'))

        return self.process_enrollment(request, domain_name, cert_profile)


@method_decorator(csrf_exempt, name='dispatch')
class EstSimpleReEnrollmentView(LoggerMixin, View):
    """Handles simple EST (Enrollment over Secure Transport) reenrollment requests.

    This view processes certificate signing requests (CSRs), authenticates the client using
    either Mutual TLS or username/password, validates the device, and issues the requested certificate
    based on the certificate template specified in the request.
    """

    EVENT = Events.est_simplereenroll

    def post(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        """Handle POST requests for simple reenrollment."""
        self.logger.info('Request received: method=%s path=%s', request.method, request.path)
        del args

        # TODO: This should really be done by the message parser,  # noqa: FIX002, TD002
        # it also needs to handle the case where one or both are omitted
        try:
            domain_name = cast('str', kwargs.get('domain'))
            cert_profile = cast('str', kwargs.get('cert_profile'))

            ctx = EstCertificateRequestContext(
                raw_message=request,
                protocol='est',
                operation='simplereenroll',
                domain_str=domain_name,
                cert_profile_str=cert_profile,
                event=self.EVENT
            )

        except Exception:
            err_msg = 'Failed to set up request context.'
            self.logger.exception(err_msg)
            return LoggedHttpResponse(err_msg, status=500)

        try:
            validator = EstHttpRequestValidator()
            validator.validate(ctx)

            parser = EstMessageParser()
            ctx = cast('EstCertificateRequestContext', parser.parse(ctx))

            est_authenticator = EstAuthentication()
            est_authenticator.authenticate(ctx)

            est_authorizer = EstAuthorization(
                allowed_operations=['simplereenroll']
            )
            est_authorizer.authorize(ctx)

            WorkflowHandler().handle(ctx)

            OperationProcessor().process_operation(ctx)

            EstMessageResponder.build_response(ctx)

        except Exception:
            self.logger.exception('Error processing EST simplereenroll request')
            EstErrorMessageResponder.build_response(ctx)

        return ctx.to_http_response()



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

                ca_credential_serializer = (
                    cast('CredentialModel', requested_domain.issuing_ca.credential)
                    .get_credential_serializer()
                )
                pkcs7_certs = ca_credential_serializer.get_full_chain_as_serializer().as_pkcs7_der()
                b64_pkcs7 = base64.b64encode(pkcs7_certs).decode()

                formatted_b64_pkcs7 = '\n'.join([b64_pkcs7[i : i + 64] for i in range(0, len(b64_pkcs7), 64)])

                http_response = LoggedHttpResponse(
                    formatted_b64_pkcs7.encode(),
                    status=200,
                    content_type='application/pkcs7-mime',
                    headers={'Content-Transfer-Encoding': 'base64'},
                )

                if 'Vary' in http_response:
                    del http_response['Vary']
                if 'Content-Language' in http_response:
                    del http_response['Content-Language']

            if not http_response:
                http_response = LoggedHttpResponse('Something went wrong during EST getcacerts.', status=500)

        except Exception:
            self.logger.exception('Error retrieving CA certificates')
            return LoggedHttpResponse('Error retrieving CA certificates', status=500)
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

        return LoggedHttpResponse('csrattrs/ is not supported', status=404)
