"""WBM push-result operation processor."""
from __future__ import annotations

from typing import TYPE_CHECKING

from django.utils import timezone

from agents.models import AgentAssignedProfile
from agents.wbm.request_context import WbmAgentRequestContext
from request.operation_processor.base import AbstractOperationProcessor
from trustpoint.logger import LoggerMixin

if TYPE_CHECKING:
    from request.request_context import BaseRequestContext


class WbmPushResultProcessor(AbstractOperationProcessor, LoggerMixin):
    """Record the push result reported by the agent on the assigned profile."""

    def process_operation(self, context: BaseRequestContext) -> None:
        """Update the assigned profile's last_certificate_update on success."""
        if not isinstance(context, WbmAgentRequestContext):
            return

        if context.push_result_profile_id is None:
            exc_msg = 'push_result_profile_id not set on context.'
            raise ValueError(exc_msg)

        raw_status = context.push_result_status or ''
        succeeded = raw_status == 'succeeded'

        if succeeded:
            updated = AgentAssignedProfile.objects.filter(
                pk=context.push_result_profile_id,
            ).update(
                last_certificate_update=timezone.now(),
                next_certificate_update_scheduled=None,
            )

            if not updated:
                exc_msg = (
                    f'AgentAssignedProfile {context.push_result_profile_id} not found '
                    'when attempting to record push result.'
                )
                raise ValueError(exc_msg)

        self.logger.info(
            'Push result for profile %s: status=%s detail=%s.',
            context.push_result_profile_id,
            raw_status,
            context.push_result_detail,
        )
