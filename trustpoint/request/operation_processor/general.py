"""Carries out the requested operation after authentication and authorization."""

from cmp.util import PKIFailureInfo
from request.request_context import BaseCertificateRequestContext, BaseRequestContext, BaseRevocationRequestContext
from trustpoint.logger import LoggerMixin

from .base import AbstractOperationProcessor
from .issue_cert import CertificateIssueProcessor
from .revoke_cert import CertificateRevocationProcessor

class OperationProcessor(AbstractOperationProcessor, LoggerMixin):
    """Chooses the appropriate operation processor based on the context."""

    def process_operation(self, context: BaseRequestContext) -> None:
        """Process the requested operation."""
        processor_instance: AbstractOperationProcessor
        if isinstance(context, BaseCertificateRequestContext):
            # Process certificate issuance operation
            processor_instance = CertificateIssueProcessor()
        elif isinstance(context, BaseRevocationRequestContext):
            # Process certificate revocation operation
            processor_instance = CertificateRevocationProcessor()
        else:
            context.error('No suitable operation processor available for the given context.',
                          http_status=500, cmp_code=PKIFailureInfo.SYSTEM_FAILURE)
            exc_msg = f'No suitable operation processor available for the given context {context}.'
            raise ValueError(exc_msg)
        
        try:
            return processor_instance.process_operation(context)
        except Exception as e:
            context.error(f'Operation processing failed: {str(e)}',
                          http_status=500, cmp_code=PKIFailureInfo.SYSTEM_FAILURE)
            self.logger.error(f'Operation processing failed: {str(e)}')
            raise
