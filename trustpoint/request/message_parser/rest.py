# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Provides classes for parsing REST API PKI messages."""

from __future__ import annotations

import contextlib
import json

from cryptography import x509

from pki.services.csr import decode_base64_csr, load_csr, validate_csr_size
from request.request_context import BaseRequestContext, RestBaseRequestContext, RestCertificateRequestContext
from trustpoint.logger import LoggerMixin

from .base import CertProfileParsing, CompositeParsing, DomainParsing, ParsingComponent
from .csr import CsrSignatureVerification
from .http import BasicAuthHeaderParsing


class RestAuthorizationHeaderParsing(BasicAuthHeaderParsing):
    """Parse Basic Auth credentials for REST requests."""

    context_type = RestBaseRequestContext
    context_error_message = 'RestAuthorizationHeaderParsing requires a RestBaseRequestContext.'
    protocol = 'rest'


class RestPkiMessageParsing(ParsingComponent, LoggerMixin):
    """Parse a JSON body containing a CSR for REST certificate enrollment requests.

    Expected JSON format::

        {
            "csr": "<PEM or Base64-DER encoded PKCS#10 CSR>"
        }
    """

    def parse(self, context: BaseRequestContext) -> None:
        """Decode REST JSON/CSR transport and parse a single PKCS#10 request."""
        if not isinstance(context, RestCertificateRequestContext):
            exc_msg = 'RestPkiMessageParsing requires a RestCertificateRequestContext.'
            raise TypeError(exc_msg)
        if context.raw_message is None:
            msg = 'Raw message is missing from the context.'
            raise ValueError(msg)
        if not hasattr(context.raw_message, 'body') or not context.raw_message.body:
            msg = 'Raw message is missing body.'
            raise ValueError(msg)
        error_message = 'Failed to parse JSON body.'
        try:
            body = context.raw_message.body
            validate_csr_size(len(body), transport=True)
            data = json.loads(body.decode('utf-8') if isinstance(body, bytes) else body)
        except (ValueError, TypeError) as exc:
            context.error(error_message, http_status=400)
            raise ValueError(error_message) from exc
        if not isinstance(data, dict):
            context.error(error_message, http_status=400)
            raise ValueError(error_message)  # noqa: TRY004 - HTTP parsers expose validation failures as ValueError.
        csr_value = data.get('csr')
        if not csr_value:
            error_message = "Missing 'csr' field in JSON body."
            context.error(error_message, http_status=400)
            raise ValueError(error_message)
        error_message = 'Failed to parse the CSR from JSON body.'
        if not isinstance(csr_value, str):
            context.error(error_message, http_status=400)
            raise ValueError(error_message)  # noqa: TRY004 - Preserve the parser's validation error contract.
        try:
            csr_bytes = csr_value.encode('utf-8')
            csr = (
                load_csr(csr_bytes, encoding='pem') if csr_bytes.lstrip().startswith(b'-----BEGIN')
                else load_csr(decode_base64_csr(csr_bytes), encoding='der')
            )
            context.cert_requested = csr
            subject_cn = 'unknown'
            with contextlib.suppress(IndexError, AttributeError):
                cn_value = csr.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
                subject_cn = cn_value if isinstance(cn_value, str) else cn_value.decode('utf-8')
            self.logger.info('REST PKI message parsing successful: subject CN: %s', subject_cn)
        except Exception as exc:
            self.logger.exception('REST PKI message parsing failed')
            context.error(error_message, http_status=400)
            raise ValueError(error_message) from exc


class RestCsrSignatureVerification(CsrSignatureVerification):
    """Verify CSR signatures for REST certificate requests."""

    context_type = RestCertificateRequestContext
    protocol = 'REST'
    missing_csr_message = 'CSR not found in the parsing context.'
    invalid_csr_message = 'Expected a CertificateSigningRequest object.'
    invalid_csr_exception = TypeError


class RestMessageParser(CompositeParsing):
    """Parser for REST-specific HTTP requests."""

    def __init__(self) -> None:
        """Initialize the composite parser with the default set of parsing components."""
        super().__init__()
        self.add(RestAuthorizationHeaderParsing())
        self.add(RestPkiMessageParsing())
        self.add(DomainParsing())
        self.add(CertProfileParsing())
        self.add(RestCsrSignatureVerification())
