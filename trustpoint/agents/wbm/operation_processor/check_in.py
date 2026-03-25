"""WBM check-in operation processor."""
from __future__ import annotations

from typing import TYPE_CHECKING, Any

from django.utils import timezone

from agents.models import AgentAssignedProfile
from agents.wbm.request_context import WbmAgentRequestContext
from request.operation_processor.base import AbstractOperationProcessor
from trustpoint.logger import LoggerMixin

if TYPE_CHECKING:
    from request.request_context import BaseRequestContext


class WbmCheckInProcessor(AbstractOperationProcessor, LoggerMixin):
    """Discover due assigned profiles for the calling agent and return renewal descriptors.

    A profile is *due* when ``next_certificate_update`` is in the past, which
    covers both automatic renewal (``last_certificate_update + threshold``) and
    operator-forced renewal (``next_certificate_update_scheduled`` set to a past
    datetime).
    """

    def process_operation(self, context: BaseRequestContext) -> None:
        """Populate ``context.pending_jobs`` with descriptors for each due profile."""
        if not isinstance(context, WbmAgentRequestContext):
            return

        if context.agent is None:
            exc_msg = 'Agent not set on context.'
            raise ValueError(exc_msg)

        profiles = (
            AgentAssignedProfile.objects.filter(agent=context.agent, enabled=True)
            .select_related('workflow_definition', 'agent__device')
        )

        now = timezone.now()
        context.pending_jobs = [
            self._build_descriptor(profile)
            for profile in profiles
            if profile.next_certificate_update <= now
        ]
        self.logger.info(
            'Check-in for agent %s: %d profile(s) pending.',
            context.agent.agent_id,
            len(context.pending_jobs),
        )

    # -- helpers ---------------------------------------------------------------

    @staticmethod
    def _build_descriptor(profile: AgentAssignedProfile) -> dict[str, Any]:
        """Build a renewal descriptor for *profile*."""
        # key_spec, subject, certificate_profile_name and workflow steps all
        # come from the workflow definition's profile JSON.
        workflow_profile: dict[str, Any] = (
            profile.workflow_definition.profile if profile.workflow_definition else {}
        )
        key_spec: str = workflow_profile.get('key_algorithm', 'EC_P256')
        subject: dict[str, str] = workflow_profile.get('subject', {})

        device = profile.agent.device
        base_url = f'https://{device.ip_address}' if device and device.ip_address else ''

        return {
            'profile_id': profile.pk,
            'base_url': base_url,
            'key_spec': key_spec,
            'subject': subject,
            'workflow': workflow_profile,
        }
