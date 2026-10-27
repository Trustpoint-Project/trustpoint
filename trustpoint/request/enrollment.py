# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Shared enrollment sequencing with explicit protocol and authentication adapters."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, cast

from request.authentication import RestAuthentication
from request.authorization import EstAuthorization, RestAuthorization
from request.message_parser import EstMessageParser, RestMessageParser
from request.message_responder import EstMessageResponder, RestMessageResponder
from request.operation_processor.general import OperationProcessor
from request.request_context import BaseCertificateRequestContext, BaseRequestContext
from request.request_validator.http_req import EstHttpRequestValidator, RestHttpRequestValidator
from request.security_hardening import (
    authenticate_est_request,
    process_certificate_operation_atomically,
    require_single_security_config,
)
from request.workflow2_issuance import release_delivered_workflow2_request
from request.workflows2_handler import Workflow2Handler

if TYPE_CHECKING:
    from collections.abc import Callable
    from typing import Literal

    from devices.models import DeviceModel
    from request.request_context import EstCertificateRequestContext, RestCertificateRequestContext


def process_workflow_operation[Context: BaseRequestContext](
    context: Context,
    process: Callable[[Context], None],
) -> None:
    """Dispatch workflows before issuing, and never process a stopped request."""
    result = Workflow2Handler().handle(context)
    if not result.should_stop:
        process(context)


@dataclass
class EnrollmentOrchestrator[Context: BaseCertificateRequestContext]:
    """Run enrollment stages and retain the current context even if a later stage fails.

    Parsers may replace their context. Keeping it on the orchestrator lets the
    view render the correct protocol error without losing that replacement.
    Views own exception handling and transport-specific error responses.
    """

    context: Context
    validate: Callable[[Context], None]
    parse: Callable[[Context], Context]
    authenticate: Callable[[Context], None]
    authorize: Callable[[Context], None]
    process: Callable[[Context], None]
    respond: Callable[[Context], None]

    def run(self) -> None:
        """Validate, authenticate, authorize, dispatch, process, then deliver."""
        self.validate(self.context)
        self.context = self.parse(self.context)
        self.authenticate(self.context)
        self.authorize(self.context)
        process_workflow_operation(self.context, self.process)
        self.respond(self.context)
        release_delivered_workflow2_request(self.context)


def _authenticate_est(context: EstCertificateRequestContext) -> None:
    require_single_security_config(context)
    authenticate_est_request(context)


def est_enrollment(
    context: EstCertificateRequestContext,
    *,
    operation: Literal['simpleenroll', 'simplereenroll'],
) -> EnrollmentOrchestrator[EstCertificateRequestContext]:
    """Configure EST's fail-closed security checks and atomic issuance."""
    return EnrollmentOrchestrator(
        context=context,
        validate=lambda ctx: EstHttpRequestValidator().validate(ctx),
        parse=lambda ctx: cast('EstCertificateRequestContext', EstMessageParser().parse(ctx)),
        authenticate=_authenticate_est,
        authorize=lambda ctx: EstAuthorization(allowed_operations=[operation]).authorize(ctx),
        process=lambda ctx: process_certificate_operation_atomically(ctx, OperationProcessor()),
        respond=EstMessageResponder.build_response,
    )


def _rest_enrollment(
    context: RestCertificateRequestContext,
    *,
    operation: Literal['enroll', 'reenroll'],
    authenticate: Callable[[RestCertificateRequestContext], None],
) -> EnrollmentOrchestrator[RestCertificateRequestContext]:
    return EnrollmentOrchestrator(
        context=context,
        validate=lambda ctx: RestHttpRequestValidator().validate(ctx),
        parse=lambda ctx: cast('RestCertificateRequestContext', RestMessageParser().parse(ctx)),
        authenticate=authenticate,
        authorize=lambda ctx: RestAuthorization(allowed_operations=[operation]).authorize(ctx),
        process=lambda ctx: OperationProcessor().process_operation(ctx),
        respond=RestMessageResponder.build_response,
    )


def rest_enrollment(
    context: RestCertificateRequestContext,
    *,
    operation: Literal['enroll', 'reenroll'],
) -> EnrollmentOrchestrator[RestCertificateRequestContext]:
    """Configure enrollment authenticated by device credentials on the REST endpoint."""
    return _rest_enrollment(
        context,
        operation=operation,
        authenticate=lambda ctx: RestAuthentication().authenticate(ctx),
    )


def authenticated_rest_enrollment(
    context: RestCertificateRequestContext,
    *,
    device: DeviceModel,
) -> EnrollmentOrchestrator[RestCertificateRequestContext]:
    """Bind the device selected by the authenticated management API, then authorize.

    The API view must authenticate the management user and validate the selected
    no-onboarding device before calling this adapter. Device HTTP credentials
    are not used for this entry point.
    """

    def bind_device(ctx: RestCertificateRequestContext) -> None:
        ctx.device = device

    return _rest_enrollment(context, operation='enroll', authenticate=bind_device)
