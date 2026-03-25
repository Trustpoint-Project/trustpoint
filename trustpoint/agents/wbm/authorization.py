"""WBM-specific authorization components."""
from __future__ import annotations

from typing import TYPE_CHECKING

from agents.models import AgentAssignedProfile
from agents.wbm.request_context import WbmAgentRequestContext
from request.authorization.base import AuthorizationComponent
from trustpoint.logger import LoggerMixin

if TYPE_CHECKING:
    from request.request_context import BaseRequestContext


class WbmSubmitCsrAuthorization(AuthorizationComponent, LoggerMixin):
    """Ensure the assigned profile referenced in submit-csr belongs to the calling agent.

    Fetches the :class:`~agents.models.AgentAssignedProfile` and stores it on
    the context so the operation processor does not need to repeat the query.
    """

    def authorize(self, context: BaseRequestContext) -> None:
        """Verify profile ownership and state; store profile on context."""
        if not isinstance(context, WbmAgentRequestContext):
            return
        if context.operation != 'submit-csr':
            return

        profile = (
            AgentAssignedProfile.objects.select_related(
                'workflow_definition', 'agent__device__domain'
            )
            .filter(
                pk=context.submit_csr_profile_id,
                agent=context.agent,
                enabled=True,
            )
            .first()
        )
        if profile is None:
            exc_msg = 'Assigned profile not found or not enabled.'
            raise ValueError(exc_msg)
        context.submit_csr_profile = profile
        self.logger.debug(
            'WBM submit-csr authorization passed for profile %s', profile.pk
        )


class WbmPushResultAuthorization(AuthorizationComponent, LoggerMixin):
    """Ensure the assigned profile referenced in push-result belongs to the calling agent."""

    def authorize(self, context: BaseRequestContext) -> None:
        """Verify the agent owns the referenced assigned profile."""
        if not isinstance(context, WbmAgentRequestContext):
            return
        if context.operation != 'push-result':
            return

        exists = AgentAssignedProfile.objects.filter(
            pk=context.push_result_profile_id,
            agent=context.agent,
            enabled=True,
        ).exists()
        if not exists:
            exc_msg = 'Assigned profile not found or not enabled.'
            raise ValueError(exc_msg)
        self.logger.debug(
            'WBM push-result authorization passed for profile %s',
            context.push_result_profile_id,
        )
