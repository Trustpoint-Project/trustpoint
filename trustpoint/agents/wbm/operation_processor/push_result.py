"""WBM push-result operation processor."""
from __future__ import annotations

from typing import TYPE_CHECKING

from django.utils import timezone

from agents.models import AgentJob
from agents.wbm.request_context import WbmAgentRequestContext
from request.operation_processor.base import AbstractOperationProcessor
from trustpoint.logger import LoggerMixin

if TYPE_CHECKING:
    from request.request_context import BaseRequestContext


class WbmPushResultProcessor(AbstractOperationProcessor, LoggerMixin):
    """Close the WBM job with the result reported by the agent."""

    def process_operation(self, context: BaseRequestContext) -> None:
        """Update the job status and record the completion timestamp."""
        if not isinstance(context, WbmAgentRequestContext):
            return

        if context.push_result_job_id is None:
            exc_msg = 'push_result_job_id not set on context.'
            raise ValueError(exc_msg)

        # Map incoming status string to a known Status choice; default to FAILED.
        raw_status = context.push_result_status or ''
        valid_statuses = {s.value for s in AgentJob.Status}
        status = raw_status if raw_status in valid_statuses else AgentJob.Status.FAILED

        updated = AgentJob.objects.filter(
            pk=context.push_result_job_id,
            status=AgentJob.Status.IN_PROGRESS,
        ).update(
            status=status,
            result_detail=context.push_result_detail,
            completed_at=timezone.now(),
        )

        if not updated:
            exc_msg = (
                f'Job {context.push_result_job_id} not found or not in IN_PROGRESS state '
                'when attempting to close it.'
            )
            raise ValueError(exc_msg)

        self.logger.info(
            'Job %s closed with status=%s.',
            context.push_result_job_id,
            status,
        )
