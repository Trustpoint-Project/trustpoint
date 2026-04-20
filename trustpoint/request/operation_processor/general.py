"""Carries out the requested operation after authentication and authorization."""

from cmp.util import PKIFailureInfo
from request.request_context import (
    BaseCertificateRequestContext,
    BaseRequestContext,
    BaseRevocationRequestContext,
    CmpBaseRequestContext,
    CmpCertConfRequestContext,
    CmpCertificateRequestContext,
    CmpPollRequestContext,
)
from trustpoint.logger import LoggerMixin

from .base import AbstractOperationProcessor
from .cert_conf import CertConfProcessor
from .cmp_certificate_request import CmpCertificateRequestProcessor
from .cmp_poll import CmpPollProcessor
from .issue_cert import CertificateIssueProcessor
from .revoke_cert import CertificateRevocationProcessor


class OperationProcessor(AbstractOperationProcessor, LoggerMixin):
    """Chooses the appropriate operation processor based on the context."""

    def process_operation(self, context: BaseRequestContext) -> None:
        """Process the requested operation."""
        processor_instance: AbstractOperationProcessor
        if isinstance(context, CmpPollRequestContext):
            processor_instance = CmpPollProcessor()
        elif isinstance(context, CmpCertConfRequestContext):
            processor_instance = CertConfProcessor()
        elif isinstance(context, CmpCertificateRequestContext):
            processor_instance = CmpCertificateRequestProcessor()
        elif isinstance(context, BaseCertificateRequestContext):
            processor_instance = CertificateIssueProcessor()
        elif isinstance(context, BaseRevocationRequestContext):
            processor_instance = CertificateRevocationProcessor()
        else:
            context.error(
                'No suitable operation processor available for the given context.',
                http_status=500,
                cmp_code=PKIFailureInfo.SYSTEM_FAILURE,
            )
            exc_msg = f'No suitable operation processor available for the given context {context}.'
            raise TypeError(exc_msg)

        try:
            return processor_instance.process_operation(context)
        except Exception:
            cmp_code = PKIFailureInfo.SYSTEM_FAILURE
            error_msg = 'PKI Operation processing failed.'

            if isinstance(context, CmpBaseRequestContext):
                if context.error_code:
                    cmp_code = context.error_code
                if context.error_details:
                    error_msg = context.error_details

            context.error(error_msg, http_status=500, cmp_code=cmp_code)
            self.logger.exception('Operation processing failed')
            raise
