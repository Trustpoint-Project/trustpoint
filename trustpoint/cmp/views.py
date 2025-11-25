"""This module contains the CMP endpoints (views)."""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
from django.views.generic.base import View
from est.views import LoggedHttpResponse  # TEMP
from request.authentication import CmpAuthentication
from request.authorization import CmpAuthorization
from request.cmp_responder import CmpMessageResponder
from request.http_request_validator import CmpHttpRequestValidator
from request.operation_processor import CertificateIssueProcessor
from request.pki_message_parser import CmpMessageParser
from request.profile_validator import ProfileValidator
from request.request_context import RequestContext

if TYPE_CHECKING:
    from typing import Any
    from django.http import HttpRequest, HttpResponse


@method_decorator(csrf_exempt, name='dispatch')
class CmpInitializationRequestView(View):
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

        ctx = RequestContext(
            raw_message=request,
            domain_str=domain_name,
            protocol='cmp',
            operation='initialization',
            cert_profile_str=cert_profile
        )

        validator = CmpHttpRequestValidator()
        validator.validate(ctx)

        parser = CmpMessageParser()
        parser.parse(ctx)

        authenticator = CmpAuthentication()
        authenticator.authenticate(ctx)

        authorizer = CmpAuthorization(
            ['initialization', 'certification']
        )
        authorizer.authorize(ctx)

        ProfileValidator.validate(ctx)

        CertificateIssueProcessor().process_operation(ctx)

        CmpMessageResponder.build_response(ctx)

        return LoggedHttpResponse(content=ctx.http_response_content,
                                  status=ctx.http_response_status,
                                  content_type=ctx.http_response_content_type)


@method_decorator(csrf_exempt, name='dispatch')
class CmpCertificationRequestView(View):
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

        ctx = RequestContext(
            raw_message=request,
            domain_str=domain_name,
            protocol='cmp',
            operation='certification',
            cert_profile_str=cert_profile
        )

        validator = CmpHttpRequestValidator()
        validator.validate(ctx)

        parser = CmpMessageParser()
        parser.parse(ctx)

        authenticator = CmpAuthentication()
        authenticator.authenticate(ctx)

        authorizer = CmpAuthorization(
            ['certification']
        )
        authorizer.authorize(ctx)

        ProfileValidator.validate(ctx)

        CertificateIssueProcessor().process_operation(ctx)

        CmpMessageResponder.build_response(ctx)

        return LoggedHttpResponse(content=ctx.http_response_content,
                                  status=ctx.http_response_status,
                                  content_type=ctx.http_response_content_type)
