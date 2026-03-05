"""WBM submit-csr operation processor."""
from __future__ import annotations

from typing import TYPE_CHECKING

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding

from agents.models import WbmJob
from agents.wbm.request_context import WbmAgentRequestContext
from request.operation_processor.base import AbstractOperationProcessor
from request.operation_processor.issue_cert import CertificateIssueProcessor
from request.request_context import EstCertificateRequestContext
from trustpoint.logger import LoggerMixin

if TYPE_CHECKING:
    from request.request_context import BaseRequestContext


class WbmSubmitCsrProcessor(AbstractOperationProcessor, LoggerMixin):
    """Sign the agent's CSR and store the resulting certificate on the job.

    Adapts the :class:`~agents.wbm.request_context.WbmAgentRequestContext` into
    an :class:`~request.request_context.EstCertificateRequestContext` and
    delegates to the existing :class:`~request.operation_processor.issue_cert.CertificateIssueProcessor`
    so that certificate issuance logic lives in exactly one place.
    """

    def process_operation(self, context: BaseRequestContext) -> None:
        """Sign the CSR and write ``cert_pem`` / ``ca_bundle_pem`` onto the job."""
        if not isinstance(context, WbmAgentRequestContext):
            return

        job = context.submit_csr_job
        if job is None:
            exc_msg = 'submit_csr_job not set on context.'
            raise ValueError(exc_msg)
        if not context.submit_csr_csr_pem:
            exc_msg = 'submit_csr_csr_pem not set on context.'
            raise ValueError(exc_msg)

        target = job.target
        device = target.device
        domain = device.domain

        if domain is None:
            exc_msg = (
                f'Device "{device}" has no domain assigned. '
                'Cannot issue certificate without a domain/issuing CA.'
            )
            raise ValueError(exc_msg)

        # Parse the PEM-encoded CSR submitted by the agent.
        csr = x509.load_pem_x509_csr(context.submit_csr_csr_pem.encode())

        # Store the raw CSR on the job record before attempting issuance.
        WbmJob.objects.filter(pk=job.pk).update(csr_pem=context.submit_csr_csr_pem)

        # Build a minimal EstCertificateRequestContext that CertificateIssueProcessor accepts.
        issue_ctx = EstCertificateRequestContext(
            raw_message=context.raw_message,
            protocol='agent',
            operation='submit-csr',
            domain_str=domain.unique_name,
            domain=domain,
            device=device,
            cert_profile_str=target.certificate_profile.unique_name,
            certificate_profile_model=target.certificate_profile,
            cert_requested=csr,
        )

        CertificateIssueProcessor().process_operation(issue_ctx)

        if issue_ctx.issued_certificate is None:
            exc_msg = 'CertificateIssueProcessor did not set issued_certificate.'
            raise ValueError(exc_msg)

        # Serialise the issued certificate and chain to PEM.
        cert_pem = issue_ctx.issued_certificate.public_bytes(Encoding.PEM).decode()
        chain_pems = [
            c.public_bytes(Encoding.PEM).decode()
            for c in (issue_ctx.issued_certificate_chain or [])
        ]
        ca_bundle_pem = ''.join(chain_pems)

        # Persist the signed certificate and advance the job to IN_PROGRESS.
        WbmJob.objects.filter(pk=job.pk).update(
            cert_pem=cert_pem,
            ca_bundle_pem=ca_bundle_pem,
            status=WbmJob.Status.IN_PROGRESS,
        )

        # Refresh the in-memory job so the responder sees the latest values.
        job.refresh_from_db()

        self.logger.info(
            'CSR signed for job %s (device=%s, profile=%s).',
            job.pk,
            device,
            target.certificate_profile.unique_name,
        )
