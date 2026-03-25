"""WBM submit-csr operation processor."""
from __future__ import annotations

from typing import TYPE_CHECKING, Any

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding

from agents.wbm.request_context import WbmAgentRequestContext
from request.operation_processor.base import AbstractOperationProcessor
from request.operation_processor.issue_cert import CertificateIssueProcessor
from request.request_context import EstCertificateRequestContext
from trustpoint.logger import LoggerMixin

if TYPE_CHECKING:
    from request.request_context import BaseRequestContext


class WbmSubmitCsrProcessor(AbstractOperationProcessor, LoggerMixin):
    """Sign the agent's CSR using the certificate profile named in the workflow definition.

    Adapts the :class:`~agents.wbm.request_context.WbmAgentRequestContext` into
    an :class:`~request.request_context.EstCertificateRequestContext` and
    delegates to the existing :class:`~request.operation_processor.issue_cert.CertificateIssueProcessor`
    so that certificate issuance logic lives in exactly one place.

    The certificate profile unique name is read from
    ``workflow_definition.profile['certificate_request']['certificate_profile']``.
    """

    def process_operation(self, context: BaseRequestContext) -> None:
        """Sign the CSR and write ``submit_csr_cert_pem`` / ``submit_csr_ca_bundle_pem`` onto the context."""
        if not isinstance(context, WbmAgentRequestContext):
            return

        assigned_profile = context.submit_csr_profile
        if assigned_profile is None:
            exc_msg = 'submit_csr_profile not set on context.'
            raise ValueError(exc_msg)
        if not context.submit_csr_csr_pem:
            exc_msg = 'submit_csr_csr_pem not set on context.'
            raise ValueError(exc_msg)

        device = assigned_profile.agent.device
        if device is None:
            exc_msg = (
                f'Agent "{assigned_profile.agent}" has no device assigned. '
                'Cannot issue certificate without an associated device.'
            )
            raise ValueError(exc_msg)

        domain = device.domain
        if domain is None:
            exc_msg = (
                f'Device "{device}" has no domain assigned. '
                'Cannot issue certificate without a domain/issuing CA.'
            )
            raise ValueError(exc_msg)

        # Resolve the certificate profile name from the workflow definition JSON.
        cert_profile_unique_name = self._get_cert_profile_name(assigned_profile.workflow_definition.profile)

        from pki.models import CertificateProfileModel  # noqa: PLC0415

        certificate_profile = CertificateProfileModel.objects.filter(
            unique_name=cert_profile_unique_name
        ).first()
        if certificate_profile is None:
            exc_msg = (
                f'Certificate profile "{cert_profile_unique_name}" not found. '
                "Check the workflow definition's certificate_request.certificate_profile field."
            )
            raise ValueError(exc_msg)

        # Parse the PEM-encoded CSR submitted by the agent.
        csr = x509.load_pem_x509_csr(context.submit_csr_csr_pem.encode())

        # Build a minimal EstCertificateRequestContext that CertificateIssueProcessor accepts.
        issue_ctx = EstCertificateRequestContext(
            raw_message=context.raw_message,
            protocol='agent',
            operation='submit-csr',
            domain_str=domain.unique_name,
            domain=domain,
            device=device,
            cert_profile_str=certificate_profile.unique_name,
            certificate_profile_model=certificate_profile,
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

        # Store the PEM results on the context for the responder.
        context.submit_csr_cert_pem = cert_pem
        context.submit_csr_ca_bundle_pem = ca_bundle_pem

        self.logger.info(
            'CSR signed for assigned profile %s (device=%s, cert_profile=%s).',
            assigned_profile.pk,
            device,
            certificate_profile.unique_name,
        )

    @staticmethod
    def _get_cert_profile_name(workflow_profile: dict[str, Any]) -> str:
        """Extract the certificate profile unique name from the workflow definition JSON.

        Reads ``profile['certificate_request']['certificate_profile']``.
        """
        cert_request: dict[str, Any] = workflow_profile.get('certificate_request', {})
        name: str = cert_request.get('certificate_profile', '')
        if not name:
            exc_msg = (
                'Workflow definition profile is missing '
                '"certificate_request.certificate_profile". '
                'Add this field to the profile JSON to specify which certificate profile to use.'
            )
            raise ValueError(exc_msg)
        return name
