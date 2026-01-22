"""Carries out the requested operation after authentication and authorization."""

from cmp.util import PKIFailureInfo
from request.request_context import BaseCertificateRequestContext, BaseRequestContext

from .base import AbstractOperationProcessor
from .issue_cert import CertificateIssueProcessor


class OperationProcessor(AbstractOperationProcessor):
    """Chooses the appropriate operation processor based on the context."""

    def process_operation(self, context: BaseRequestContext) -> None:
        """Process the requested operation."""
        if isinstance(context, BaseCertificateRequestContext):
            # Process certificate issuance operation
            return CertificateIssueProcessor().process_operation(context)

        context.error('No suitable operation processor available for the given context.',
                      http_status=500, cmp_code=PKIFailureInfo.SYSTEM_FAILURE)
        exc_msg = f'No suitable operation processor available for the given context {context}.'
        raise ValueError(exc_msg)
