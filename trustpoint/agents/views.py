"""Generic pipeline view mixin for all Trustpoint agent API endpoints."""
from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from django.utils.decorators import method_decorator
from django.views import View
from django.views.decorators.csrf import csrf_exempt

from agents.authentication import AgentAuthentication
from agents.authorization import AgentActiveAuthorization
from agents.request_context import AgentRequestContext
from trustpoint.logger import LoggerMixin

if TYPE_CHECKING:
    from django.http import HttpRequest, HttpResponse

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
