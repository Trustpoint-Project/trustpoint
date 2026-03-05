"""Generic authentication for all Trustpoint agent API endpoints."""
from __future__ import annotations

import hashlib
from typing import TYPE_CHECKING

from django.utils import timezone

from agents.models import TrustpointAgent
from agents.request_context import AgentRequestContext
from request.authentication.base import AuthenticationComponent
from trustpoint.logger import LoggerMixin

if TYPE_CHECKING:
    from request.request_context import BaseRequestContext


class AgentAuthentication(AuthenticationComponent, LoggerMixin):
    """Authenticate any Trustpoint agent via its mTLS client-certificate fingerprint.

    Protocol-agnostic: works for any :class:`AgentRequestContext` sub-class.
    Reads the DER-encoded client certificate from ``SSL_CLIENT_CERT_DER``,
    computes its SHA-256 fingerprint, and looks up the matching
    :class:`~agents.models.TrustpointAgent` record.  Raises ``ValueError`` on
    failure, consistent with all other authentication components.
    """

    def authenticate(self, context: BaseRequestContext) -> None:
        """Resolve the agent and store it on the context."""
        if not isinstance(context, AgentRequestContext):
            return

        if context.raw_message is None:
            exc_msg = 'No raw HTTP request in context.'
            raise ValueError(exc_msg)

        der: bytes | None = context.raw_message.META.get('SSL_CLIENT_CERT_DER')
        if der is None:
            self.logger.warning('Agent request received without a client certificate.')
            exc_msg = 'No client certificate presented.'
            raise ValueError(exc_msg)

        fingerprint = hashlib.sha256(der).hexdigest().upper()

        try:
            agent = TrustpointAgent.objects.get(
                certificate_fingerprint=fingerprint,
                is_active=True,
            )
        except TrustpointAgent.DoesNotExist:
            self.logger.warning(
                'Agent authentication failed: unknown or inactive fingerprint %s',
                fingerprint,
            )
            exc_msg = 'Unknown or inactive agent.'
            raise ValueError(exc_msg) from None

        TrustpointAgent.objects.filter(pk=agent.pk).update(last_seen_at=timezone.now())
        context.agent = agent
        self.logger.info('Agent authenticated: %s', agent.agent_id)
