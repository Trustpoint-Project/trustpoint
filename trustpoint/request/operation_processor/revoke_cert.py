"""Certificate revocation operation processor classes."""

from request.request_context import (
    BaseRequestContext,
    BaseRevocationRequestContext,
)

from .base import AbstractOperationProcessor


class CertificateRevocationProcessor(AbstractOperationProcessor):
    """Operation processor for revoking certificates."""

    def process_operation(self, context: BaseRequestContext) -> None:
        """Process the certificate revocation operation."""
        if not isinstance(context, BaseRevocationRequestContext):
            exc_msg = 'Certificate revocation requires a subclass of BaseCertificateRequestContext.'
            raise TypeError(exc_msg)
        # decide which processor to use based on domain configuration
        if context.domain and context.domain.issuing_ca:
            processor = LocalCaCertificateRevocationProcessor()
            return processor.process_operation(context)

        exc_msg = 'No suitable operation processor found for certificate revocation.'
        raise ValueError(exc_msg)


class LocalCaCertificateRevocationProcessor(CertificateRevocationProcessor):
    """Operation processor for revoking certificates via a local CA."""

    def process_operation(self, context: BaseRequestContext) -> None:
        """Process the certificate revocation operation."""
        if not isinstance(context, BaseRevocationRequestContext):
            exc_msg = 'Certificate revocation requires a subclass of BaseRevocationRequestContext.'
            raise TypeError(exc_msg)
        if not context.device:
            exc_msg = 'Device must be set in the context to revoke a certificate.'
            raise ValueError(exc_msg)
        if not context.domain:
            exc_msg = 'Domain must be set in the context to revoke a certificate.'
            raise ValueError(exc_msg)
        if not context.credential_to_revoke:
            exc_msg = 'Credential to revoke must be set in the context to revoke a certificate.'
            raise ValueError(exc_msg)
        
        ca = context.domain.get_issuing_ca_or_value_error()
        context.issuer_credential =  ca.get_credential()

        context.credential_to_revoke.revoke()
