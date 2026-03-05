"""Generic request context for all Trustpoint agent API endpoints."""
from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from request.request_context import RestBaseRequestContext

if TYPE_CHECKING:
    from agents.models import TrustpointAgent


@dataclass(kw_only=True)
class AgentRequestContext(RestBaseRequestContext):
    """Base request context for all Trustpoint agent API endpoints.

    Holds only the resolved :class:`~agents.models.TrustpointAgent` identity
    plus the HTTP fields inherited from :class:`~request.request_context.RestBaseRequestContext`.
    Capability-specific sub-classes (e.g. :class:`~agents.wbm.request_context.WbmAgentRequestContext`)
    extend this with the fields needed by their own parsers, processors and responders.
    """

    # Set by AgentAuthentication; None until authentication succeeds.
    agent: TrustpointAgent | None = None
