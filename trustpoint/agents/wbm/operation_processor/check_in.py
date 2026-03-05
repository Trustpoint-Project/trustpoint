"""WBM check-in operation processor."""
from __future__ import annotations

from typing import TYPE_CHECKING, Any

from django.utils import timezone

from agents.models import AgentCertificateTarget, AgentJob
from agents.wbm.request_context import WbmAgentRequestContext
from pki.models import IssuedCredentialModel
from request.operation_processor.base import AbstractOperationProcessor
from trustpoint.logger import LoggerMixin

if TYPE_CHECKING:
    from request.request_context import BaseRequestContext


class WbmCheckInProcessor(AbstractOperationProcessor, LoggerMixin):
    """Discover due targets for the calling agent and create PENDING_CSR jobs.

    A target is *due* when either:

    - ``push_requested`` is ``True`` (operator-triggered), or
    - The most recently issued certificate expires within
      ``target.renewal_threshold_days`` days (automatic renewal window).

    For each due target a :class:`~agents.models.WbmJob` with status
    ``PENDING_CSR`` is created and ``push_requested`` is cleared atomically.
    """

    def process_operation(self, context: BaseRequestContext) -> None:
        """Populate ``context.pending_jobs`` with descriptors for each due target."""
        if not isinstance(context, WbmAgentRequestContext):
            return

        if context.agent is None:
            exc_msg = 'Agent not set on context.'
            raise ValueError(exc_msg)

        targets = (
            AgentCertificateTarget.objects.filter(agent=context.agent, enabled=True)
            .select_related('device', 'certificate_profile', 'workflow')
        )

        context.pending_jobs = [
            self._create_job(target) for target in targets if self._is_due(target)
        ]
        self.logger.info(
            'Check-in for agent %s: %d job(s) pending.',
            context.agent.agent_id,
            len(context.pending_jobs),
        )

    # -- helpers ---------------------------------------------------------------

    @staticmethod
    def _is_due(target: AgentCertificateTarget) -> bool:
        """Return True if the target needs a certificate push in this cycle."""
        if target.push_requested:
            return True
        if target.renewal_threshold_days == 0:
            return False

        latest = (
            IssuedCredentialModel.objects.filter(
                device=target.device,
                issued_using_cert_profile=target.certificate_profile.unique_name,
            )
            .select_related('credential__certificate')
            .order_by('-created_at')
            .first()
        )
        if latest is None:
            # No certificate has ever been issued — treat as due.
            return True

        cert = latest.credential.certificate
        if cert is None:
            return True

        days_left = (cert.not_valid_after - timezone.now()).days
        return days_left < target.renewal_threshold_days

    @staticmethod
    def _create_job(target: AgentCertificateTarget) -> dict[str, Any]:
        """Create a PENDING_CSR job for *target* and return its descriptor dict."""
        # Determine key_spec and subject from the certificate profile.
        profile = target.certificate_profile.profile
        key_spec: str = profile.get('key_algorithm', 'EC_P256')
        subject: dict[str, str] = profile.get('subject', {})

        job = AgentJob.objects.create(
            target=target,
            status=AgentJob.Status.PENDING_CSR,
            key_spec=key_spec,
            subject=subject,
        )

        # Clear the operator-requested flag atomically (no race with other workers).
        AgentCertificateTarget.objects.filter(pk=target.pk).update(push_requested=False)

        return {
            'job_id': job.pk,
            'base_url': target.base_url,
            'key_spec': job.key_spec,
            'subject': job.subject,
            'workflow': target.workflow.profile,
        }
