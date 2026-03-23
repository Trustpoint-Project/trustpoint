"""Views for REST PKI certificate enrollment and re-enrollment."""

from typing import Any, cast

from django.http import HttpRequest, HttpResponse
from django.utils.decorators import method_decorator
from django.views import View
from django.views.decorators.csrf import csrf_exempt

from request.authentication import RestAuthentication
from request.authorization import RestAuthorization
from request.message_parser import RestMessageParser
from request.message_responder import RestErrorMessageResponder, RestMessageResponder
from request.operation_processor.general import OperationProcessor
from request.request_context import RestCertificateRequestContext
from request.request_validator import RestHttpRequestValidator
from request.workflow_handler import WorkflowHandler
from trustpoint.logger import LoggerMixin
from workflows.events import Events


@method_decorator(csrf_exempt, name='dispatch')
class RestEnrollView(LoggerMixin, View):
    """Handles REST certificate enrollment requests (initial enrollment).

    POST /.well-known/rest/<domain>/<cert_profile>/enroll/

    Request body (JSON)::

        {
            "csr": "<PEM or Base64-DER encoded PKCS#10 CSR>"
        }

    Authentication: HTTP Basic Auth (username:password) or mTLS client certificate.

    Response (JSON, HTTP 200)::

        {
            "certificate": "<PEM certificate>",
            "certificate_chain": ["<PEM ca cert>", ...]
        }
    """

    EVENT = Events.rest_enroll

    def post(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        """Handle POST requests for REST certificate enrollment."""
        del args
        self.logger.info('REST enroll request received: method=%s path=%s', request.method, request.path)

        domain_name = cast('str', kwargs.get('domain'))
        cert_profile = cast('str', kwargs.get('cert_profile', 'domain_credential'))

        try:
            ctx = RestCertificateRequestContext(
                raw_message=request,
                protocol='rest',
                operation='enroll',
                domain_str=domain_name,
                cert_profile_str=cert_profile,
                event=self.EVENT,
            )
        except Exception:
            err_msg = 'Failed to set up REST request context.'
            self.logger.exception(err_msg)
            return HttpResponse(err_msg, status=500, content_type='application/json')

        try:
            validator = RestHttpRequestValidator()
            validator.validate(ctx)

            parser = RestMessageParser()
            ctx = cast('RestCertificateRequestContext', parser.parse(ctx))

            authenticator = RestAuthentication()
            authenticator.authenticate(ctx)

            authorizer = RestAuthorization(allowed_operations=['enroll'])
            authorizer.authorize(ctx)

            WorkflowHandler().handle(ctx)

            OperationProcessor().process_operation(ctx)

            RestMessageResponder.build_response(ctx)

        except Exception:
            self.logger.exception('Error processing REST enroll request')
            RestErrorMessageResponder.build_response(ctx)

        return ctx.to_http_response()


@method_decorator(csrf_exempt, name='dispatch')
class RestReEnrollView(LoggerMixin, View):
    """Handles REST certificate re-enrollment requests.

    Request body (JSON)::

        {
            "csr": "<PEM or Base64-DER encoded PKCS#10 CSR>"
        }

    Response (JSON, HTTP 200)::

        {
            "certificate": "<PEM certificate>",
            "certificate_chain": ["<PEM ca cert>", ...]
        }
    """

    EVENT = Events.rest_reenroll

    def post(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        """Handle POST requests for REST certificate re-enrollment."""
        del args
        self.logger.info('REST reenroll request received: method=%s path=%s', request.method, request.path)

        domain_name = cast('str', kwargs.get('domain'))
        cert_profile = cast('str', kwargs.get('cert_profile'))

        try:
            ctx = RestCertificateRequestContext(
                raw_message=request,
                protocol='rest',
                operation='reenroll',
                domain_str=domain_name,
                cert_profile_str=cert_profile,
                event=self.EVENT,
            )
        except Exception:
            err_msg = 'Failed to set up REST request context.'
            self.logger.exception(err_msg)
            return HttpResponse(err_msg, status=500, content_type='application/json')

        try:
            validator = RestHttpRequestValidator()
            validator.validate(ctx)

            parser = RestMessageParser()
            ctx = cast('RestCertificateRequestContext', parser.parse(ctx))

            authenticator = RestAuthentication()
            authenticator.authenticate(ctx)

            authorizer = RestAuthorization(allowed_operations=['reenroll'])
            authorizer.authorize(ctx)

            WorkflowHandler().handle(ctx)

            OperationProcessor().process_operation(ctx)

            RestMessageResponder.build_response(ctx)

        except Exception:
            self.logger.exception('Error processing REST reenroll request')
            RestErrorMessageResponder.build_response(ctx)

        return ctx.to_http_response()
