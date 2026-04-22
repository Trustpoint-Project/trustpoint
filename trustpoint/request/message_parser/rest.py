"""Provides classes for parsing REST API PKI messages."""

from __future__ import annotations

import base64
import contextlib
import json
from typing import Never

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.asymmetric.ec import ECDSA
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15

from request.request_context import BaseRequestContext, RestBaseRequestContext, RestCertificateRequestContext
from trustpoint.logger import LoggerMixin

from .base import CertProfileParsing, CompositeParsing, DomainParsing, ParsingComponent


class RestAuthorizationHeaderParsing(ParsingComponent, LoggerMixin):
    """Parse the HTTP Basic Auth Authorization header for REST requests."""

    def parse(self, context: BaseRequestContext) -> None:
        """Extract username and password from the Basic Auth Authorization header."""
        if not isinstance(context, RestBaseRequestContext):
            exc_msg = 'RestAuthorizationHeaderParsing requires a RestBaseRequestContext.'
            raise TypeError(exc_msg)

        if context.raw_message is None:
            error_message = 'Raw message is missing from the context.'
            self.logger.warning('REST auth header parsing failed: Raw message is missing')
            raise ValueError(error_message)

        if not hasattr(context.raw_message, 'headers') or not context.raw_message.headers:
            error_message = 'Raw message is missing headers.'
            self.logger.warning('REST auth header parsing failed: Headers are missing')
            raise ValueError(error_message)

        auth_header = context.raw_message.headers.get('Authorization')
        if not auth_header:
            self.logger.debug('REST auth header parsing skipped: No Authorization header present')
            return

        if not auth_header.lower().startswith('basic '):
            error_message = "Authorization header must start with 'Basic'."
            self.logger.warning("REST auth header parsing failed: Header does not start with 'Basic'")
            raise ValueError(error_message)

        try:
            credentials = base64.b64decode(auth_header.split(' ', 1)[1].strip()).decode('utf-8')
            rest_username, rest_password = credentials.split(':', 1)
            context.rest_username = rest_username
            context.rest_password = rest_password
            self.logger.debug("REST auth header parsing successful: Extracted credentials for user '%s'", rest_username)
        except Exception as e:
            error_message = "Malformed 'Authorization' header credentials."
            self.logger.warning('REST auth header parsing failed: Malformed credentials - %s', e)
            context.error(error_message, http_status=401)
            raise ValueError(error_message) from e


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


class RestCsrSignatureVerification(ParsingComponent, LoggerMixin):
    """Verify the CSR signature for REST requests."""

    def _raise_validation_error(self, message: str) -> Never:
        """Raise a ValueError with the given message."""
        raise ValueError(message)

    def parse(self, context: BaseRequestContext) -> None:
        """Validate the signature of the CSR stored in the context."""
        if not isinstance(context, RestCertificateRequestContext):
            exc_msg = 'RestCsrSignatureVerification requires a RestCertificateRequestContext.'
            raise TypeError(exc_msg)

        csr = context.cert_requested
        if csr is None:
            err_msg = 'CSR not found in the parsing context.'
            self.logger.warning('REST CSR signature verification failed: CSR not found')
            self._raise_validation_error(err_msg)

        if not isinstance(csr, x509.CertificateSigningRequest):
            err_msg = 'Expected a CertificateSigningRequest object.'
            self.logger.warning('REST CSR signature verification failed: Wrong type %s', type(csr).__name__)
            raise TypeError(err_msg)

        public_key = csr.public_key()
        signature_hash_algorithm = csr.signature_hash_algorithm

        if signature_hash_algorithm is None:
            error_message = 'CSR does not contain a signature hash algorithm.'
            self.logger.warning('REST CSR signature verification failed: No signature hash algorithm')
            self._raise_validation_error(error_message)

        if not isinstance(public_key, (rsa.RSAPublicKey, ec.EllipticCurvePublicKey)):
            error_message = 'Unsupported public key type for CSR signature verification.'
            self.logger.warning('REST CSR signature verification failed: Unsupported public key type %s',
                                type(public_key).__name__)
            raise TypeError(error_message)

        try:
            key_type = 'RSA' if isinstance(public_key, rsa.RSAPublicKey) else 'EC'

            if isinstance(public_key, rsa.RSAPublicKey):
                public_key.verify(
                    csr.signature,
                    csr.tbs_certrequest_bytes,
                    PKCS1v15(),
                    signature_hash_algorithm,
                )
            elif isinstance(public_key, ec.EllipticCurvePublicKey):
                public_key.verify(
                    csr.signature,
                    csr.tbs_certrequest_bytes,
                    ECDSA(signature_hash_algorithm),
                )

            self.logger.info('REST CSR signature verification successful: %s key with %s hash',
                             key_type, signature_hash_algorithm.name)
        except Exception as e:
            error_message = 'Failed to verify the CSR signature.'
            self.logger.exception('REST CSR signature verification failed')
            raise ValueError(error_message) from e


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
