"""This module contains the CMP endpoints (views)."""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
from django.views.generic.base import View

from est.views import LoggedHttpResponse  # TEMP
from request.authentication import CmpAuthentication
from request.authorization import CmpAuthorization
from request.message_parser import CmpMessageParser
from request.message_responder.cmp import CmpMessageResponder
from request.operation_processor import CertificateIssueProcessor
from request.profile_validator import ProfileValidator
from request.request_context import BaseRequestContext, CmpCertificateRequestContext
from request.request_validator.http_req import CmpHttpRequestValidator
from trustpoint.logger import LoggerMixin

if TYPE_CHECKING:
    from typing import Any

    from django.http import HttpRequest, HttpResponse


@method_decorator(csrf_exempt, name='dispatch')
class CmpInitializationRequestView(LoggerMixin, View):
    """Handles CMP Initialization Request Messages."""

    http_method_names = ('post',)

    def post(
        self,
        request: HttpRequest,
        *args: Any,
        **kwargs: Any,
    ) -> HttpResponse:
        """Handles the POST requests to the CMP IR endpoint."""
        del args
        domain_name = cast('str', kwargs.get('domain_name'))
        # Default to 'domain_credential' if not provided
        cert_profile = cast('str', kwargs.get('certificate_profile', 'domain_credential'))

        ctx: BaseRequestContext
        try:
            ctx = CmpCertificateRequestContext(
                raw_message=request,
                domain_str=domain_name,
                protocol='cmp',
                operation='initialization',
                cert_profile_str=cert_profile
        )
        except Exception:
            err_msg = 'Failed to set up CMP request context.'
            self.logger.exception(err_msg)
            return LoggedHttpResponse(err_msg, status=500)

        try:
            validator = CmpHttpRequestValidator()
            validator.validate(ctx)

            parser = CmpMessageParser()
            ctx = parser.parse(ctx)

            authenticator = CmpAuthentication()
            authenticator.authenticate(ctx)

            authorizer = CmpAuthorization(
                ['initialization', 'certification']
            )
            authorizer.authorize(ctx)

            ProfileValidator.validate(ctx)

            CertificateIssueProcessor().process_operation(ctx)
        except Exception:
            self.logger.exception('Error processing CMP request')

        CmpMessageResponder.build_response(ctx)

        return ctx.to_http_response()


@method_decorator(csrf_exempt, name='dispatch')
class CmpCertificationRequestView(LoggerMixin, View):
    """Handles CMP Certification Request Messages."""

    http_method_names = ('post',)

    def post(
        self,
        request: HttpRequest,
        *args: Any,
        **kwargs: Any,
    ) -> HttpResponse:
        """Handles the POST requests to the CMP CR endpoint."""
        del args
        domain_name = cast('str', kwargs.get('domain_name'))
        # Default to 'tls_client' if not provided (TBD)
        cert_profile = cast('str', kwargs.get('certificate_profile', 'tls_client'))

        ctx: BaseRequestContext
        try:
            ctx = CmpCertificateRequestContext(
                raw_message=request,
                domain_str=domain_name,
                protocol='cmp',
                operation='certification',
                cert_profile_str=cert_profile
            )
        except Exception:
            err_msg = 'Failed to set up CMP request context.'
            self.logger.exception(err_msg)
            return LoggedHttpResponse(err_msg, status=500)

        try:
            validator = CmpHttpRequestValidator()
            validator.validate(ctx)

            parser = CmpMessageParser()
            ctx = parser.parse(ctx)

            authenticator = CmpAuthentication()
            authenticator.authenticate(ctx)

            authorizer = CmpAuthorization(
                ['certification']
            )
            authorizer.authorize(ctx)

            ProfileValidator.validate(ctx)

            CertificateIssueProcessor().process_operation(ctx)
        except Exception:
            self.logger.exception('Error processing CMP request')

        CmpMessageResponder.build_response(ctx)

        return ctx.to_http_response()
