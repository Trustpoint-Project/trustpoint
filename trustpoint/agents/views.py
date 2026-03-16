"""Generic pipeline view mixin for all Trustpoint agent API endpoints."""
from __future__ import annotations

import json
from dataclasses import dataclass
from typing import TYPE_CHECKING

from django.utils.decorators import method_decorator
from django.views import View
from django.views.decorators.csrf import csrf_exempt
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView

from agents.authentication import AgentAuthentication
from agents.authorization import AgentActiveAuthorization
from agents.request_context import AgentRequestContext
from trustpoint.logger import LoggerMixin

if TYPE_CHECKING:
    from django.http import HttpRequest, HttpResponse
    from rest_framework.request import Request

    from request.authorization.base import AuthorizationComponent
    from request.message_parser.base import ParsingComponent
    from request.message_responder.base import AbstractMessageResponder
    from request.operation_processor.base import AbstractOperationProcessor


@dataclass
class AgentPipelineConfig:
    """Groups all per-operation pipeline components into a single parameter object.

    Using a dataclass avoids the linter's too-many-arguments restriction on
    :meth:`AgentPipelineMixin._run_pipeline` while keeping every stage explicit.
    """

    parser: ParsingComponent
    extra_authorizers: list[AuthorizationComponent]
    processor: AbstractOperationProcessor
    responder: AbstractMessageResponder
    error_responder: AbstractMessageResponder


class AgentPipelineMixin(LoggerMixin):
    """Generic request-pipeline runner for all Trustpoint agent API endpoints.

    Sub-classes set :attr:`context_class` to the capability-specific context type
    (e.g. ``WbmAgentRequestContext``).  The pipeline stages are:

    1. Parser - populates operation-specific input fields on the context
    2. AgentAuthentication - resolves ``context.agent`` via mTLS fingerprint
    3. AgentActiveAuthorization - guards ``is_active``
    4. Extra authorizers - capability-specific ownership / state checks
    5. Processor - performs the work, sets output fields
    6. Responder - serialises output into ``context.http_response_*``

    Any exception in steps 1-6 is caught and handed to the error responder.
    """

    #: Override in sub-classes with the capability-specific context class.
    context_class: type[AgentRequestContext] = AgentRequestContext

    def _run_pipeline(
        self,
        request: HttpRequest,
        operation: str,
        config: AgentPipelineConfig,
    ) -> HttpResponse:
        """Execute the full agent pipeline for one operation.

        Args:
            request: The incoming Django HTTP request.
            operation: Short name for the operation (e.g. ``'check-in'``).
            config: Grouped pipeline components for this operation.

        Returns:
            The Django ``HttpResponse`` built by the responder or error responder.
        """
        self.logger.info(
            'Agent pipeline start: operation=%s method=%s path=%s',
            operation,
            request.method,
            request.path,
        )
        ctx = self.context_class(
            raw_message=request,
            protocol='agent',
            operation=operation,
        )
        try:
            config.parser.parse(ctx)
            AgentAuthentication().authenticate(ctx)
            AgentActiveAuthorization().authorize(ctx)
            for authorizer in config.extra_authorizers:
                authorizer.authorize(ctx)
            config.processor.process_operation(ctx)
            config.responder.build_response(ctx)
        except Exception:
            self.logger.exception(
                'Error in agent pipeline: operation=%s', operation
            )
            config.error_responder.build_response(ctx)

        return ctx.to_http_response()


@method_decorator(csrf_exempt, name='dispatch')
class AgentPipelineView(AgentPipelineMixin, View):
    """Base Django view for agent pipeline endpoints.

    Combines :class:`AgentPipelineMixin` with Django's ``View`` so that
    capability-specific view classes only need to inherit from this and
    set ``context_class``.  Import ``View`` from ``django.views`` in the
    sub-class if additional HTTP methods are needed.
    """


class AgentPipelineAPIView(AgentPipelineMixin, APIView):
    """Base DRF ``APIView`` for agent pipeline endpoints.

    Provides the same pipeline execution as :class:`AgentPipelineMixin` but
    wraps it in the DRF request/response cycle so that content-negotiation,
    OpenAPI schema generation (via ``drf-spectacular``), and DRF renderer
    classes all work correctly.

    Sub-classes must:

    * Set :attr:`~AgentPipelineMixin.context_class` to the capability-specific
      context type (e.g. ``WbmAgentRequestContext``).
    * Call :meth:`_run_api_pipeline` from their HTTP handler methods after any
      serializer validation.

    Authentication via mTLS is handled inside the pipeline by
    :class:`~agents.authentication.AgentAuthentication`, which reads
    ``request.META['SSL_CLIENT_CERT_DER']`` from the underlying Django
    ``HttpRequest``.  DRF's own authentication/permission machinery is therefore
    disabled by default.
    """

    authentication_classes = ()
    permission_classes = ()

    def _run_api_pipeline(
        self,
        request: Request,
        operation: str,
        config: AgentPipelineConfig,
    ) -> Response:
        """Execute the agent pipeline and return a DRF :class:`~rest_framework.response.Response`.

        Unwraps the underlying Django ``HttpRequest`` from the DRF ``request``
        so that ``request.META`` (including ``SSL_CLIENT_CERT_DER``) is
        accessible to :class:`~agents.authentication.AgentAuthentication`.
        The ``HttpResponse`` produced by the pipeline responder is then
        converted to a DRF ``Response``.

        Args:
            request: The incoming DRF request.
            operation: Short operation name for logging (e.g. ``'check-in'``).
            config: Grouped pipeline components for this operation.

        Returns:
            A DRF :class:`~rest_framework.response.Response` carrying the JSON
            body and HTTP status code produced by the pipeline responder.
        """
        raw_request: HttpRequest = request._request  # noqa: SLF001
        http_response = self._run_pipeline(raw_request, operation, config)

        try:
            body = json.loads(http_response.content)
        except (ValueError, AttributeError):
            body = {'detail': http_response.content.decode('utf-8', errors='replace')}

        drf_status = http_response.status_code or status.HTTP_500_INTERNAL_SERVER_ERROR
        return Response(body, status=drf_status)
