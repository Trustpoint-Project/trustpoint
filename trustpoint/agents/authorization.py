"""Generic authorization for all Trustpoint agent API endpoints."""
from __future__ import annotations

from typing import TYPE_CHECKING

from agents.request_context import AgentRequestContext
from request.authorization.base import AuthorizationComponent
from trustpoint.logger import LoggerMixin

if TYPE_CHECKING:
    from request.request_context import BaseRequestContext


class AgentActiveAuthorization(AuthorizationComponent, LoggerMixin):
    """Ensure the resolved agent is active.

    Applied to every agent endpoint regardless of capability.  The
    authentication stage already filters on ``is_active``, but this component
    makes the check explicit in the authorization stage for clarity and
    defence-in-depth.
    """

    def authorize(self, context: BaseRequestContext) -> None:
        """Raise ``ValueError`` if the agent is not active."""
        if not isinstance(context, AgentRequestContext):
            return
        if context.agent is None or not context.agent.is_active:
            exc_msg = 'Agent is not active.'
            raise ValueError(exc_msg)
        self.logger.debug('Agent active check passed for %s', context.agent.agent_id)
