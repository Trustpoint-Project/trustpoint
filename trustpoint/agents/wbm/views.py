"""WBM-specific views for the agent API endpoints."""
from __future__ import annotations

from typing import TYPE_CHECKING, Any

from django.utils.decorators import method_decorator
from django.views import View
from django.views.decorators.csrf import csrf_exempt

from agents.views import AgentPipelineConfig, AgentPipelineMixin
from agents.wbm.authorization import WbmPushResultAuthorization, WbmSubmitCsrAuthorization
from agents.wbm.message_parser import WbmCheckInParser, WbmPushResultParser, WbmSubmitCsrParser
from agents.wbm.message_responder import (
    WbmCheckInResponder,
    WbmErrorResponder,
    WbmPushResultResponder,
    WbmSubmitCsrResponder,
)
from agents.wbm.operation_processor.check_in import WbmCheckInProcessor
from agents.wbm.operation_processor.push_result import WbmPushResultProcessor
from agents.wbm.operation_processor.submit_csr import WbmSubmitCsrProcessor
from agents.wbm.request_context import WbmAgentRequestContext

if TYPE_CHECKING:
    from django.http import HttpRequest, HttpResponse


class WbmPipelineMixin(AgentPipelineMixin):
    """Pipeline mixin specialised for WBM endpoints.

    Sets :attr:`~agents.views.AgentPipelineMixin.context_class` to
    :class:`~agents.wbm.request_context.WbmAgentRequestContext` so the generic
    runner creates the right context for every WBM operation.
    """

    context_class = WbmAgentRequestContext


@method_decorator(csrf_exempt, name='dispatch')
class WbmCheckInView(WbmPipelineMixin, View):
    """GET /api/agents/wbm/check-in/ — agent polls for pending work."""

    def get(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        """Handle check-in request."""
        del args, kwargs
        return self._run_pipeline(
            request,
            operation='check-in',
            config=AgentPipelineConfig(
                parser=WbmCheckInParser(),
                extra_authorizers=[],
                processor=WbmCheckInProcessor(),
                responder=WbmCheckInResponder(),
                error_responder=WbmErrorResponder(),
            ),
        )


@method_decorator(csrf_exempt, name='dispatch')
class WbmSubmitCsrView(WbmPipelineMixin, View):
    """POST /api/agents/wbm/submit-csr/ — agent submits a CSR for signing."""

    def post(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        """Handle submit-csr request."""
        del args, kwargs
        return self._run_pipeline(
            request,
            operation='submit-csr',
            config=AgentPipelineConfig(
                parser=WbmSubmitCsrParser(),
                extra_authorizers=[WbmSubmitCsrAuthorization()],
                processor=WbmSubmitCsrProcessor(),
                responder=WbmSubmitCsrResponder(),
                error_responder=WbmErrorResponder(),
            ),
        )


@method_decorator(csrf_exempt, name='dispatch')
class WbmPushResultView(WbmPipelineMixin, View):
    """POST /api/agents/wbm/push-result/ — agent reports the outcome of a push."""

    def post(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        """Handle push-result request."""
        del args, kwargs
        return self._run_pipeline(
            request,
            operation='push-result',
            config=AgentPipelineConfig(
                parser=WbmPushResultParser(),
                extra_authorizers=[WbmPushResultAuthorization()],
                processor=WbmPushResultProcessor(),
                responder=WbmPushResultResponder(),
                error_responder=WbmErrorResponder(),
            ),
        )
