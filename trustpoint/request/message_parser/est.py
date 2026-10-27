# Copyright (c) 2025 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Provides classes for parsing EST PKI messages."""
import contextlib

from cryptography import x509

from pki.services.csr import decode_base64_csr, load_csr, validate_csr_size
from request.request_context import BaseRequestContext, EstBaseRequestContext, EstCertificateRequestContext
from trustpoint.logger import LoggerMixin

from .base import CertProfileParsing, CompositeParsing, DomainParsing, ParsingComponent
from .csr import CsrSignatureVerification
from .http import BasicAuthHeaderParsing


class EstAuthorizationHeaderParsing(BasicAuthHeaderParsing):
    """Parse Basic Auth credentials for EST requests."""

    context_type = EstBaseRequestContext
    context_error_message = 'EstAuthorizationHeaderParsing requires a subclass of EstBaseRequestContext.'
    protocol = 'est'


class EstPkiMessageParsing(ParsingComponent, LoggerMixin):
    """Component for parsing EST-specific PKI messages."""

    def parse(self, context: BaseRequestContext) -> None:
        """Decode EST's transport representation and parse a single PKCS#10 request."""
        if not isinstance(context, EstCertificateRequestContext):
            exc_msg = 'EstPkiMessageParsing requires an EstCertificateRequestContext.'
            raise TypeError(exc_msg)
        if context.raw_message is None:
            msg = 'Raw message is missing from the context.'
            raise ValueError(msg)
        if not hasattr(context.raw_message, 'body') or not context.raw_message.body:
            msg = 'Raw message is missing body.'
            raise ValueError(msg)

        try:
            body = context.raw_message.body
            validate_csr_size(len(body), transport=True)
            transfer_encoding = context.raw_message.headers.get('Content-Transfer-Encoding', '').strip().lower()
            if transfer_encoding == 'base64':
                body = decode_base64_csr(body)
            if body.lstrip().startswith(b'-----BEGIN'):
                csr = load_csr(body, encoding='pem')
                context.est_encoding = 'pem'
            else:
                der = body if body.startswith(b'\x30') else decode_base64_csr(body)
                csr = load_csr(der, encoding='der')
                context.est_encoding = 'pkcs7'
            context.cert_requested = csr
            subject_cn = 'unknown'
            with contextlib.suppress(IndexError, AttributeError):
                cn_value = csr.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
                subject_cn = cn_value if isinstance(cn_value, str) else cn_value.decode('utf-8')
            self.logger.info('EST PKI message parsing successful: %s format, subject CN: %s',
                             context.est_encoding, subject_cn)
        except Exception as exc:
            error_message = 'Failed to parse the CSR.'
            self.logger.exception('EST PKI message parsing failed')
            context.error(error_message, http_status=400)
            raise ValueError(error_message) from exc


class EstCsrSignatureVerification(CsrSignatureVerification):
    """Verify CSR signatures for EST certificate requests."""

    context_type = EstCertificateRequestContext
    protocol = 'EST'
    missing_csr_message = (
        'CSR not found in the parsing context. Ensure it was parsed before signature verification.'
    )
    invalid_csr_message = (
        'CSR signature verification only supports EST requests with CertificateSigningRequest objects.'
    )
    invalid_csr_exception = ValueError


class EstMessageParser(CompositeParsing):
    """Parser for EST-specific HTTP requests."""

    def __init__(self) -> None:
        """Initialize the composite parser with the default set of parsing components."""
        super().__init__()
        self.add(EstAuthorizationHeaderParsing())
        self.add(EstPkiMessageParsing())
        self.add(DomainParsing())
        self.add(CertProfileParsing())
        self.add(EstCsrSignatureVerification())
