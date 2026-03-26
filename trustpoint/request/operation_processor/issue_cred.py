"""Credential issuance operation processor classes."""

from cryptography.x509 import CertificateBuilder

from pki.util.keys import KeyGenerator
from request.operation_processor.issue_cert import CertificateIssueProcessor
from request.request_context import (
    BaseCredentialRequestContext,
    BaseRequestContext,
)
from request.workflows2_gate import workflow2_allows_certificate_issuance
from trustpoint.logger import LoggerMixin

from .base import AbstractOperationProcessor


class CredentialIssueProcessor(AbstractOperationProcessor, LoggerMixin):
    """Operation processor for issuing credentials."""

    def process_operation(self, context: BaseRequestContext) -> None:
        """Process the credential issuance operation."""
        if not isinstance(context, BaseCredentialRequestContext):
            exc_msg = 'Credential issuance requires a subclass of BaseCredentialRequestContext.'
            raise TypeError(exc_msg)
        if not workflow2_allows_certificate_issuance(context):
            return
        if not context.cert_requested or not isinstance(context.cert_requested, CertificateBuilder):
            exc_msg = 'Credential issuance requires a certificate request in context.'
            raise ValueError(exc_msg)
        if not context.domain:
            exc_msg = 'Credential issuance requires a domain to be set in context.'
            raise ValueError(exc_msg)
        # generate a private key
        if not context.private_key:
            private_key = KeyGenerator.generate_private_key(domain=context.domain)
            context.private_key = private_key
            context.cert_requested = context.cert_requested.public_key(private_key.as_crypto().public_key())
        CertificateIssueProcessor().process_operation(context)
