"""This module contains the CMP endpoints (views)."""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

from django.http import Http404
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
from django.views.generic.base import View

from cmp.util import PkiOperation
from est.views import LoggedHttpResponse  # TEMP
from request.authentication import CmpAuthentication
from request.authorization import CmpAuthorization
from request.message_parser import CmpMessageParser
from request.message_responder.cmp import CmpMessageResponder
from request.operation_processor.general import OperationProcessor
from request.request_context import BaseRequestContext, CmpCertificateRequestContext
from request.request_validator.http_req import CmpHttpRequestValidator
from trustpoint.logger import LoggerMixin

if TYPE_CHECKING:
    from typing import Any

    from django.http import HttpRequest, HttpResponse


@method_decorator(csrf_exempt, name='dispatch')
class CmpRequestView(LoggerMixin, View):
    """Handles all CMP Request Messages."""

    http_method_names = ('post',)

    def _extract_path_params(
        self,
        kwargs: dict[str, Any],
    ) -> tuple[str | None, str | None, str | None]:
        """Extracts domain name, certificate profile, and operation from URL path parameters."""
        domain_name = cast('str | None', kwargs.get('domain'))
        cert_profile = cast('str | None', kwargs.get('cert_profile'))
        operation = cast('str | None', kwargs.get('operation'))

        if domain_name in ['.','_']: # Handle empty domain segment
            domain_name = None

        # Handle combined 'cert_profile_or_operation' parameter
        cert_profile_or_operation = cast('str | None', kwargs.get('cert_profile_or_operation'))
        if cert_profile_or_operation:
            try:
                operation_enum = PkiOperation(cert_profile_or_operation)
            except ValueError:
                if cert_profile is not None:
                    # cert_profile is already set, so this is invalid operation
                    err_msg = f"Invalid CMP operation '{cert_profile_or_operation}' in URL."
                    raise Http404(err_msg) from None
                cert_profile = cert_profile_or_operation
            else:
                operation = operation_enum.value
        # Validate operation if present
        elif operation is not None:
            try:
                # Validate operation
                PkiOperation(operation)
            except ValueError:
                err_msg = f"Invalid CMP operation '{operation}' in URL."
                raise Http404(err_msg) from None

        # Clean trailing '~' from domain name if present (due to profile syntax, but no profile given)
        if domain_name and domain_name.endswith('~'):
            domain_name = domain_name[:-1]

        return domain_name, cert_profile, operation

    def post(
        self,
        request: HttpRequest,
        *args: Any,
        **kwargs: Any,
    ) -> HttpResponse:
        """Handles the POST requests to the CMP IR endpoint."""
        del args
        domain_name, cert_profile, operation = self._extract_path_params(kwargs)
        if not cert_profile:
            cert_profile = 'domain_credential'

        ctx: BaseRequestContext
        try:
            ctx = CmpCertificateRequestContext(
                raw_message=request,
                domain_str=domain_name,
                protocol='cmp',
                operation=operation,
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
                ['initialization', 'certification', 'revocation']
            )
            authorizer.authorize(ctx)

            OperationProcessor().process_operation(ctx)
        except Exception:
            self.logger.exception('Error processing CMP request')

        CmpMessageResponder.build_response(ctx)

        return ctx.to_http_response()
