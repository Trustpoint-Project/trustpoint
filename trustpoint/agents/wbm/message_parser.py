"""WBM message parsers for the three agent API endpoints."""
from __future__ import annotations

import json
from typing import TYPE_CHECKING

from agents.wbm.request_context import WbmAgentRequestContext
from request.message_parser.base import ParsingComponent
from trustpoint.logger import LoggerMixin

if TYPE_CHECKING:
    from request.request_context import BaseRequestContext


class WbmCheckInParser(ParsingComponent, LoggerMixin):
    """Parse a GET /check-in/ request.

    No request body - agent identity is resolved by AgentAuthentication.
    """

    def parse(self, context: BaseRequestContext) -> None:
        """Set operation; no body fields to parse for check-in."""
        if not isinstance(context, WbmAgentRequestContext):
            return
        context.operation = 'check-in'


class WbmSubmitCsrParser(ParsingComponent, LoggerMixin):
    """Parse a POST /submit-csr/ request body into context fields."""

    def parse(self, context: BaseRequestContext) -> None:
        """Extract ``job_id`` and ``csr_pem`` from the JSON body."""
        if not isinstance(context, WbmAgentRequestContext):
            return
        context.operation = 'submit-csr'

        if context.raw_message is None:
            exc_msg = 'No raw HTTP request in context.'
            raise ValueError(exc_msg)

        try:
            body: dict = json.loads(context.raw_message.body)
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            exc_msg = 'Request body is not valid JSON.'
            raise ValueError(exc_msg) from exc

        job_id = body.get('job_id')
        csr_pem = body.get('csr_pem', '')

        if job_id is None:
            exc_msg = "'job_id' is required."
            raise ValueError(exc_msg)
        if not csr_pem:
            exc_msg = "'csr_pem' is required."
            raise ValueError(exc_msg)

        context.submit_csr_job_id = int(job_id)
        context.submit_csr_csr_pem = csr_pem


class WbmPushResultParser(ParsingComponent, LoggerMixin):
    """Parse a POST /push-result/ request body into context fields."""

    def parse(self, context: BaseRequestContext) -> None:
        """Extract ``job_id``, ``status``, and ``detail`` from the JSON body."""
        if not isinstance(context, WbmAgentRequestContext):
            return
        context.operation = 'push-result'

        if context.raw_message is None:
            exc_msg = 'No raw HTTP request in context.'
            raise ValueError(exc_msg)

        try:
            body: dict = json.loads(context.raw_message.body)
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            exc_msg = 'Request body is not valid JSON.'
            raise ValueError(exc_msg) from exc

        job_id = body.get('job_id')
        if job_id is None:
            exc_msg = "'job_id' is required."
            raise ValueError(exc_msg)

        from agents.models import WbmJob  # noqa: PLC0415 - local import avoids circular dependency at module load

        context.push_result_job_id = int(job_id)
        context.push_result_status = body.get('status', WbmJob.Status.FAILED)
        context.push_result_detail = body.get('detail', '')
