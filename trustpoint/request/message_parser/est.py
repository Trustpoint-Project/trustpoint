"""Provides classes for parsing EST PKI messages."""
import base64
import contextlib
import re
from typing import Never

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

from request.request_context import BaseRequestContext, EstBaseRequestContext, EstCertificateRequestContext
from trustpoint.logger import LoggerMixin

from .base import CertProfileParsing, CompositeParsing, DomainParsing, ParsingComponent


class EstAuthorizationHeaderParsing(ParsingComponent, LoggerMixin):
    """Validate Authorization header for HTTP Basic Auth."""

    def parse(self, context: BaseRequestContext) -> None:
        """Validate and parse the 'Authorization' header and extract credentials."""
        if not isinstance(context, EstBaseRequestContext):
            exc_msg = 'EstAuthorizationHeaderParsing requires a subclass of EstBaseRequestContext.'
            raise TypeError(exc_msg)

        if context.raw_message is None:
            error_message = 'Raw message is missing from the context.'
            self.logger.warning('Authorization header validation failed: Raw message is missing')
            raise ValueError(error_message)

        if not hasattr(context.raw_message, 'headers') or not context.raw_message.headers:
            error_message = 'Raw message is missing headers.'
            self.logger.warning('Authorization header validation failed: Raw message headers are missing')
            raise ValueError(error_message)

        auth_header = context.raw_message.headers.get('Authorization')
        if not auth_header:
            self.logger.debug('Authorization header validation skipped: No Authorization header present')
            return

        if not auth_header.lower().startswith('basic '):
            error_message = "Authorization header must start with 'Basic'."
            self.logger.warning("Authorization header validation failed: "
                                "Header does not start with 'Basic': %s...", auth_header[:20])
            raise ValueError(error_message)

        try:
            credentials = base64.b64decode(auth_header.split(' ', 1)[1].strip()).decode('utf-8')
            est_username, est_password = credentials.split(':', 1)

            context.est_username = est_username
            context.est_password = est_password
            self.logger.debug("Authorization header validation successful: "
                              "Extracted credentials for user '%s'", est_username)
        except Exception as e:
            error_message = "Malformed 'Authorization' header credentials."
            self.logger.warning('Authorization header validation failed: Malformed credentials - %s', e)
            context.error(error_message, http_status=401)
            raise ValueError(error_message) from e


class EstPkiMessageParsing(ParsingComponent, LoggerMixin):
    """Component for parsing EST-specific PKI messages."""

    def parse(self, context: BaseRequestContext) -> None:
        """Parse a DER-encoded PKCS#10 certificate signing request."""
        if not isinstance(context, EstCertificateRequestContext):
            exc_msg = 'EstPkiMessageParsing requires an EstCertificateRequestContext.'
            raise TypeError(exc_msg)

        def raise_parsing_error(message: str) -> None:
            """Helper to raise a ValueError with given error message."""
            raise ValueError(message)

        if context.raw_message is None:
            error_message = 'Raw message is missing from the context.'
            self.logger.warning('EST PKI message parsing failed: Raw message is missing')
            raise ValueError(error_message)

        if not hasattr(context.raw_message, 'body') or not context.raw_message.body:
            error_message = 'Raw message is missing body.'
            self.logger.warning('EST PKI message parsing failed: Raw message body is missing')
            raise ValueError(error_message)

        try:
            body_size = len(context.raw_message.body)

            # Our response format is based on the incoming CSR format for maximum compatibility
            # For DER-encoded CSRs (optional Base64), we respond with PKCS#7 DER (CMS, RFC 7030-compliant)
            # For PEM-encoded CSRs, we respond with the PEM-encoded certificate
            if b'CERTIFICATE REQUEST-----' in context.raw_message.body:
                est_encoding = 'pem'
                csr = x509.load_pem_x509_csr(context.raw_message.body)
                self.logger.debug('EST PKI message parsing: Detected PEM format, body size: %(body_size)s bytes',
                                   extra={'body_size': body_size})
            elif re.match(rb'^[A-Za-z0-9+/=\n]+$', context.raw_message.body):
                est_encoding = 'pkcs7' #'base64_der'
                der_data = base64.b64decode(context.raw_message.body)
                csr = x509.load_der_x509_csr(der_data)
                self.logger.debug(
                    'EST PKI message parsing: Detected Base64 DER format, '
                    'body size: %(body_size)s bytes, decoded: %(decoded_size)s bytes',
                    extra={'body_size': body_size, 'decoded_size': len(der_data)}
                )
            elif context.raw_message.body.startswith(b'\x30'):  # ASN.1 DER starts with 0x30
                est_encoding = 'pkcs7' #'der'
                csr = x509.load_der_x509_csr(context.raw_message.body)
                self.logger.debug('EST PKI message parsing: Detected DER format, body size: %(body_size)s bytes',
                                   extra={'body_size': body_size})
            else:
                self.logger.warning(
                    'EST PKI message parsing failed: Unsupported CSR format, '
                    'body size: %(body_size)s bytes',
                    extra={'body_size': body_size}
                )
                raise_parsing_error("Unsupported CSR format. Ensure it's PEM, Base64, or raw DER.")

            context.cert_requested = csr
            context.est_encoding = est_encoding

            subject_cn = 'unknown'
            with contextlib.suppress(IndexError, AttributeError):
                cn_value = csr.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
                subject_cn = cn_value if isinstance(cn_value, str) else cn_value.decode('utf-8')

            self.logger.info('EST PKI message parsing successful: %(format)s format, subject CN: %(subject_cn)s',
                             extra={'format': est_encoding, 'subject_cn': subject_cn})

        except Exception as e:
            error_message = 'Failed to parse the CSR.'
            self.logger.exception('EST PKI message parsing failed', extra={'exception': str(e)})
            raise ValueError(error_message) from e


class EstCsrSignatureVerification(ParsingComponent, LoggerMixin):
    """Parses the context to fetch the CSR and verifies its signature using the public key contained in the CSR."""

    def parse(self, context: BaseRequestContext) -> None:
        """Validates the signature of the CSR stored in the context."""
        if not isinstance(context, EstCertificateRequestContext):
            exc_msg = 'EstCsrSignatureVerification requires an EstCertificateRequestContext.'
            raise TypeError(exc_msg)

        csr = context.cert_requested
        if csr is None:
            err_msg = 'CSR not found in the parsing context. Ensure it was parsed before signature verification.'
            self.logger.warning('EST CSR signature verification failed: CSR not found in context')
            self._raise_validation_error(err_msg)

        if not isinstance(csr, x509.CertificateSigningRequest):
            err_msg = 'CSR signature verification only supports EST requests with CertificateSigningRequest objects.'
            self.logger.warning('EST CSR signature verification failed: Expected CertificateSigningRequest, got %s',
                              type(csr).__name__)
            self._raise_validation_error(err_msg)

        public_key = csr.public_key()
        signature_hash_algorithm = csr.signature_hash_algorithm

        if signature_hash_algorithm is None:
            error_message = 'CSR does not contain a signature hash algorithm.'
            self.logger.warning('EST CSR signature verification failed: No signature hash algorithm')
            raise ValueError(error_message)

        if not isinstance(public_key, (rsa.RSAPublicKey, ec.EllipticCurvePublicKey)):
            error_message = 'Unsupported public key type for CSR signature verification.'
            self.logger.warning(
                'EST CSR signature verification failed: Unsupported public key type',
                extra={'public_key_type': str(type(public_key))})
            raise TypeError(error_message)

        try:
            key_type = 'RSA' if isinstance(public_key, rsa.RSAPublicKey) else 'EC'

            if isinstance(public_key, rsa.RSAPublicKey):
                public_key.verify(
                    signature=csr.signature,
                    data=csr.tbs_certrequest_bytes,
                    padding=padding.PKCS1v15(),
                    algorithm=signature_hash_algorithm,
                )
            elif isinstance(public_key, ec.EllipticCurvePublicKey):
                public_key.verify(
                    signature=csr.signature,
                    data=csr.tbs_certrequest_bytes,
                    signature_algorithm=ec.ECDSA(signature_hash_algorithm),
                )

            self.logger.info('EST CSR signature verification successful: %s key with %s hash',
                             key_type, signature_hash_algorithm.name)
        except Exception as e:
            error_message = 'Failed to verify the CSR signature.'
            self.logger.exception('EST CSR signature verification failed', extra={'exception': str(e)})
            raise ValueError(error_message) from e

    def _raise_validation_error(self, message: str) -> Never:
        """Raise a ValueError with the given message."""
        raise ValueError(message)


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
