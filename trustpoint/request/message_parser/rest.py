# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Provides classes for parsing REST API PKI messages."""

from __future__ import annotations

import base64
import contextlib
import json

from cryptography import x509

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
        """Parse the JSON body and extract the CSR."""
        if not isinstance(context, RestCertificateRequestContext):
            exc_msg = 'RestPkiMessageParsing requires a RestCertificateRequestContext.'
            raise TypeError(exc_msg)

        if context.raw_message is None:
            error_message = 'Raw message is missing from the context.'
            self.logger.warning('REST PKI message parsing failed: Raw message is missing')
            raise ValueError(error_message)

        if not hasattr(context.raw_message, 'body') or not context.raw_message.body:
            error_message = 'Raw message is missing body.'
            self.logger.warning('REST PKI message parsing failed: Body is missing')
            raise ValueError(error_message)

        try:
            body = context.raw_message.body
            data = json.loads(body.decode('utf-8') if isinstance(body, bytes) else body)
        except (json.JSONDecodeError, UnicodeDecodeError) as e:
            error_message = 'Failed to parse JSON body.'
            self.logger.warning('REST PKI message parsing failed: Invalid JSON - %s', e)
            context.error(error_message, http_status=400)
            raise ValueError(error_message) from e

        csr_value = data.get('csr')
        if not csr_value:
            error_message = "Missing 'csr' field in JSON body."
            self.logger.warning('REST PKI message parsing failed: Missing csr field')
            context.error(error_message, http_status=400)
            raise ValueError(error_message)

        try:
            csr_bytes = csr_value.encode('utf-8') if isinstance(csr_value, str) else csr_value

            if b'CERTIFICATE REQUEST' in csr_bytes:
                csr = x509.load_pem_x509_csr(csr_bytes)
                self.logger.debug('REST PKI message parsing: Detected PEM CSR')
            else:
                # Assume Base64-encoded DER
                der_data = base64.b64decode(csr_bytes)
                csr = x509.load_der_x509_csr(der_data)
                self.logger.debug('REST PKI message parsing: Detected Base64-DER CSR')

            context.cert_requested = csr

            subject_cn = 'unknown'
            with contextlib.suppress(IndexError, AttributeError):
                cn_value = csr.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
                subject_cn = cn_value if isinstance(cn_value, str) else cn_value.decode('utf-8')

            self.logger.info('REST PKI message parsing successful: subject CN: %s', subject_cn)

        except Exception as e:
            error_message = 'Failed to parse the CSR from JSON body.'
            self.logger.exception('REST PKI message parsing failed')
            context.error(error_message, http_status=400)
            raise ValueError(error_message) from e


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
