"""WBM message responders for the three agent API endpoints."""
from __future__ import annotations

import json
from typing import TYPE_CHECKING

from agents.request_context import AgentRequestContext
from agents.wbm.request_context import WbmAgentRequestContext
from request.message_responder.base import AbstractMessageResponder

if TYPE_CHECKING:
    from request.request_context import BaseRequestContext

_JSON_CONTENT_TYPE = 'application/json'


class WbmCheckInResponder(AbstractMessageResponder):
    """Build the JSON response for a successful check-in."""

    @staticmethod
    def build_response(context: BaseRequestContext) -> None:
        """Serialise pending jobs and poll interval into the context response fields."""
        if not isinstance(context, WbmAgentRequestContext):
            return

        payload = {
            'poll_interval_seconds': context.agent.poll_interval_seconds if context.agent else 300,
            'jobs': context.pending_jobs,
        }
        context.http_response_status = 200
        context.http_response_content_type = _JSON_CONTENT_TYPE
        context.http_response_content = json.dumps(payload)


class WbmSubmitCsrResponder(AbstractMessageResponder):
    """Build the JSON response for a successful submit-csr."""

    @staticmethod
    def build_response(context: BaseRequestContext) -> None:
        """Return the signed certificate and CA bundle from the job."""
        if not isinstance(context, WbmAgentRequestContext):
            return

        job = context.submit_csr_job
        if job is None:
            exc_msg = 'submit_csr_job not set; cannot build submit-csr response.'
            raise ValueError(exc_msg)

        payload = {
            'cert_pem': job.cert_pem,
            'ca_bundle_pem': job.ca_bundle_pem,
        }
        context.http_response_status = 200
        context.http_response_content_type = _JSON_CONTENT_TYPE
        context.http_response_content = json.dumps(payload)


class WbmPushResultResponder(AbstractMessageResponder):
    """Build the empty 200 response for a successful push-result."""

    @staticmethod
    def build_response(context: BaseRequestContext) -> None:
        """Acknowledge receipt of the push result."""
        if not isinstance(context, WbmAgentRequestContext):
            return

        context.http_response_status = 200
        context.http_response_content_type = _JSON_CONTENT_TYPE
        context.http_response_content = json.dumps({'status': 'ok'})


class WbmErrorResponder(AbstractMessageResponder):
    """Build a generic JSON error response for any agent pipeline failure."""

    @staticmethod
    def build_response(context: BaseRequestContext) -> None:
        """Write a 500 JSON error body unless the context has already set a status."""
        if not isinstance(context, AgentRequestContext):
            return

        # Only override if no status was already set by a prior stage.
        if context.http_response_status is None:
            context.http_response_status = 500

        context.http_response_content_type = _JSON_CONTENT_TYPE
        context.http_response_content = json.dumps({'error': 'An internal error occurred.'})
