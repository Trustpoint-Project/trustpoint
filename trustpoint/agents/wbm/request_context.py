"""WBM-specific request context for agent API endpoints."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from agents.request_context import AgentRequestContext

if TYPE_CHECKING:
    from agents.models import WbmJob


@dataclass(kw_only=True)
class WbmAgentRequestContext(AgentRequestContext):
    """Request context for all three WBM agent API endpoints.

    Extends :class:`~agents.request_context.AgentRequestContext` with
    WBM-specific input/output fields.  Each pipeline stage populates only
    the fields it is responsible for:

    - Parser        -> ``operation`` + operation-specific *input* fields
    - Authorizer    -> validates inputs, stores fetched DB objects (e.g. ``submit_csr_job``)
    - Processor     -> performs the work, sets *output* fields
    - Responder     -> serialises output fields into ``http_response_*``
    """

    # -- check-in output (set by WbmCheckInProcessor) -------------------------
    pending_jobs: list[dict[str, Any]] = field(default_factory=list)

    # -- submit-csr input / output --------------------------------------------
    # Set by WbmSubmitCsrParser
    submit_csr_job_id: int | None = None
    submit_csr_csr_pem: str | None = None
    # Set by WbmSubmitCsrAuthorization (fetched once, shared with processor)
    submit_csr_job: WbmJob | None = None

    # -- push-result input ----------------------------------------------------
    # Set by WbmPushResultParser
    push_result_job_id: int | None = None
    push_result_status: str | None = None
    push_result_detail: str = ''
