# Copyright (c) 2024 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""This module contains the CMP endpoints (views)."""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

from django.http import Http404
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
from django.views.generic.base import View

from cmp.util import PkiOperation
from est.views import LoggedHttpResponse  # TEMP
from request.authorization import CmpAuthorization
from request.message_parser import CmpMessageParser
from request.message_responder.cmp import CmpMessageResponder
from request.operation_processor.general import OperationProcessor
from request.request_context import (
    BaseCertificateRequestContext,
    CmpBaseRequestContext,
    CmpCertificateRequestContext,
    HttpBaseRequestContext,
)
from request.request_validator.http_req import CmpHttpRequestValidator
from request.security_hardening import (
    authenticate_cmp_request,
    mark_cmp_client_nonce,
    process_certificate_operation_atomically,
    record_cmp_response_nonce,
    require_single_security_config,
    validate_cmp_proof_of_possession,
    validate_cmp_transaction_freshness,
)
from request.workflow2_issuance import release_delivered_workflow2_request
from request.workflows2_handler import Workflow2Handler
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
        """Extract domain name, certificate profile, and operation from URL path parameters."""
        domain_name = cast('str | None', kwargs.get('domain'))
        cert_profile = cast('str | None', kwargs.get('cert_profile'))
        operation = cast('str | None', kwargs.get('operation'))

        if domain_name in ('.', '_'):
            domain_name = None

        cert_profile_or_operation = cast('str | None', kwargs.get('cert_profile_or_operation'))
        if cert_profile_or_operation:
            try:
                operation_enum = PkiOperation(cert_profile_or_operation)
            except ValueError:
                if cert_profile is not None:
                    err_msg = f"Invalid CMP operation '{cert_profile_or_operation}' in URL."
                    raise Http404(err_msg) from None
                cert_profile = cert_profile_or_operation
            else:
                operation = operation_enum.value
        elif operation is not None:
            try:
                PkiOperation(operation)
            except ValueError:
                err_msg = f"Invalid CMP operation '{operation}' in URL."
                raise Http404(err_msg) from None

        if domain_name and domain_name.endswith('~'):
            domain_name = domain_name[:-1]

        return domain_name, cert_profile, operation

    def post(
        self,
        request: HttpRequest,
        *args: Any,
        **kwargs: Any,
    ) -> HttpResponse:
        """Handle a CMP POST request through the hardened request workflow."""
        del args
        domain_name, cert_profile, operation = self._extract_path_params(kwargs)

        ctx: CmpBaseRequestContext
        try:
            ctx = CmpCertificateRequestContext(
                raw_message=request,
                domain_str=domain_name,
                protocol='cmp',
                operation=operation,
                cert_profile_str=cert_profile,
            )
        except Exception:
            err_msg = 'Failed to set up CMP request context.'
            self.logger.exception(err_msg)
            return LoggedHttpResponse(err_msg, status=500)

        try:
            CmpHttpRequestValidator().validate(ctx)
            ctx = cast('CmpBaseRequestContext', CmpMessageParser().parse(ctx))

            # Security checks that must happen before expensive or state-changing
            # authentication/authorization work.
            validate_cmp_transaction_freshness(ctx)
            if isinstance(ctx, BaseCertificateRequestContext):
                require_single_security_config(ctx)

            authenticate_cmp_request(ctx)
            validate_cmp_proof_of_possession(ctx)

            CmpAuthorization(
                ['initialization', 'certification', 'revocation', 'certconf']
            ).authorize(ctx)

            # Only persist a follow-up nonce after both authentication and
            # authorization succeeded, otherwise an attacker could burn a nonce.
            mark_cmp_client_nonce(ctx)

            workflow2_result = Workflow2Handler().handle(ctx)
            if not workflow2_result.should_stop:
                processor = OperationProcessor()
                if isinstance(ctx, BaseCertificateRequestContext):
                    process_certificate_operation_atomically(ctx, processor)
                else:
                    processor.process_operation(ctx)
        except Exception:
            self.logger.exception('Error processing CMP request')

        try:
            CmpMessageResponder.build_response(ctx)
            if isinstance(ctx, CmpBaseRequestContext):
                record_cmp_response_nonce(ctx)
            release_delivered_workflow2_request(ctx)
        except Exception:
            self.logger.exception('Error building CMP response')
            if isinstance(ctx, HttpBaseRequestContext):
                ctx.http_response_status = 500
                ctx.http_response_content = 'Internal server error building CMP response.'
                ctx.http_response_content_type = 'text/plain'

        return ctx.to_http_response()
