"""WBM-specific authorization components."""
from __future__ import annotations

from typing import TYPE_CHECKING

from agents.models import AgentJob
from agents.wbm.request_context import WbmAgentRequestContext
from request.authorization.base import AuthorizationComponent
from trustpoint.logger import LoggerMixin

if TYPE_CHECKING:
    from request.request_context import BaseRequestContext


class WbmSubmitCsrAuthorization(AuthorizationComponent, LoggerMixin):
    """Ensure the job referenced in submit-csr belongs to the calling agent.

    Fetches the :class:`~agents.models.WbmJob` and stores it on the context so
    the operation processor does not need to repeat the query.
    """

    def authorize(self, context: BaseRequestContext) -> None:
        """Verify job ownership and state; store job on context."""
        if not isinstance(context, WbmAgentRequestContext):
            return
        if context.operation != 'submit-csr':
            return

        job = (
            WbmJob.objects.select_related('target__certificate_profile', 'target__device__domain')
            .filter(
                pk=context.submit_csr_job_id,
                status=WbmJob.Status.PENDING_CSR,
                target__agent=context.agent,
            )
            .first()
        )
        if job is None:
            exc_msg = 'Job not found or not in PENDING_CSR state.'
            raise ValueError(exc_msg)
        context.submit_csr_job = job
        self.logger.debug('WBM submit-csr authorization passed for job %s', job.pk)


class WbmPushResultAuthorization(AuthorizationComponent, LoggerMixin):
    """Ensure the job referenced in push-result belongs to the calling agent."""

    def authorize(self, context: BaseRequestContext) -> None:
        """Verify the agent owns the in-progress job."""
        if not isinstance(context, WbmAgentRequestContext):
            return
        if context.operation != 'push-result':
            return

        exists = WbmJob.objects.filter(
            pk=context.push_result_job_id,
            status=WbmJob.Status.IN_PROGRESS,
            target__agent=context.agent,
        ).exists()
        if not exists:
            exc_msg = 'Job not found or not in IN_PROGRESS state.'
            raise ValueError(exc_msg)
        self.logger.debug(
            'WBM push-result authorization passed for job %s',
            context.push_result_job_id,
        )
