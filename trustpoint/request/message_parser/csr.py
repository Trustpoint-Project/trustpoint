# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Shared signature verification for HTTP certificate requests."""

from typing import ClassVar

from cryptography import x509

from pki.services.csr import CsrErrorCode, CsrValidationError, verify_csr_signature
from request.request_context import BaseCertificateRequestContext, BaseRequestContext
from trustpoint.logger import LoggerMixin

from .base import ParsingComponent


class CsrSignatureVerification(ParsingComponent, LoggerMixin):
    """Verify supported CSR signatures while retaining protocol-specific input errors."""

    context_type: ClassVar[type[BaseCertificateRequestContext]]
    protocol: ClassVar[str]
    missing_csr_message: ClassVar[str]
    invalid_csr_message: ClassVar[str]
    invalid_csr_exception: ClassVar[type[Exception]] = TypeError

    def parse(self, context: BaseRequestContext) -> None:
        """Check the CSR type, supported algorithm, and signature."""
        if not isinstance(context, self.context_type):
            article = 'an' if self.protocol == 'EST' else 'a'
            msg = f'{type(self).__name__} requires {article} {self.context_type.__name__}.'
            raise TypeError(msg)

        csr = context.cert_requested
        if csr is None:
            self.logger.warning('%s CSR signature verification failed: CSR not found', self.protocol)
            raise ValueError(self.missing_csr_message)
        if not isinstance(csr, x509.CertificateSigningRequest):
            self.logger.warning(
                '%s CSR signature verification failed: Wrong type %s', self.protocol, type(csr).__name__
            )
            raise self.invalid_csr_exception(self.invalid_csr_message)

        try:
            verify_csr_signature(csr)
        except CsrValidationError as exc:
            self.logger.warning('%s CSR signature verification failed: %s', self.protocol, exc)
            if exc.code == CsrErrorCode.UNSUPPORTED_KEY:
                msg = 'Unsupported public key type for CSR signature verification.'
                raise TypeError(msg) from exc
            if exc.code == CsrErrorCode.MISSING_HASH:
                raise ValueError(str(exc)) from exc
            msg = 'Failed to verify the CSR signature.'
            raise ValueError(msg) from exc
        self.logger.info('%s CSR signature verification successful', self.protocol)
