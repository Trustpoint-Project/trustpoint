"""Provides the `HttpRequestValidator` class for validating HTTP requests."""
import base64
import contextlib
import itertools
import urllib
from abc import ABC, abstractmethod

from cryptography import x509

from request.request_context import RequestContext
from trustpoint.logger import LoggerMixin


class ValidationComponent(ABC):
    """Abstract base class to represent a component in composite validation."""

    @abstractmethod
    def validate(self, context: RequestContext) -> None:
        """Execute validation logic and enrich context."""

class PayloadSizeValidation(ValidationComponent, LoggerMixin):
    """Validate payload size."""

    def __init__(self, max_payload_size: int) -> None:
        """Initialize the PayloadSizeValidation with the maximum allowed payload size."""
        self.max_payload_size = max_payload_size

    def validate(self, context: RequestContext) -> None:
        """Validate the payload size against the maximum allowed size."""
        if context.raw_message is None:
            error_message = 'Raw message is missing from the context.'
            self.logger.warning('Payload size validation failed: Raw message is missing')
            raise ValueError(error_message)


        if not hasattr(context.raw_message, 'body') or not context.raw_message.body:
            error_message = 'Raw message is missing body.'
            self.logger.warning('Payload size validation failed: Raw message body is missing')
            raise ValueError(error_message)

        payload_size = len(context.raw_message.body)
        if payload_size > self.max_payload_size:
            error_message = f'Payload size exceeds maximum allowed size of {self.max_payload_size} bytes.'
            self.logger.warning('Payload size validation failed: %d bytes exceeds maximum %d bytes',
                                payload_size, self.max_payload_size)
            raise ValueError(error_message)

        self.logger.debug('Payload size validation successful: %d bytes (limit: %d bytes)',
                          payload_size, self.max_payload_size)


class ContentTypeValidation(ValidationComponent, LoggerMixin):
    """Validate request content type."""

    def __init__(self, expected_content_type: str) -> None:
        """Initialize the ContentTypeValidation with the expected content type."""
        self.expected_content_type = expected_content_type

    def validate(self, context: RequestContext) -> None:
        """Validate the presence of the 'Content-Type' header and check if it matches the expected type."""
        if context.raw_message is None:
            error_message = 'Raw message is missing from the context.'
            self.logger.warning('Content type validation failed: Raw message is missing')
            raise ValueError(error_message)

        if not hasattr(context.raw_message, 'headers') or not context.raw_message.headers:
            error_message = 'Raw message is missing headers.'
            self.logger.warning('Content type validation failed: Raw message headers are missing')
            raise ValueError(error_message)

        content_type = context.raw_message.headers.get('Content-Type')
        if not content_type:
            error_message = "Missing 'Content-Type' header."
            self.logger.warning('Content type validation failed: Content-Type header is missing')
            raise ValueError(error_message)

        if content_type != self.expected_content_type:
            error_message = (
                f"Invalid 'Content-Type' header '{content_type}'. "
                f"Expected '{self.expected_content_type}'."
            )
            self.logger.warning("Content type validation failed: received '%s', expected '%s'",
                                content_type, self.expected_content_type)
            raise ValueError(error_message)

        self.logger.debug('Content type validation successful: %s', content_type)


class AcceptHeaderValidation(ValidationComponent, LoggerMixin):
    """Validate the Accept header."""
    # TODO(FHK): not mandatory # noqa: FIX002

    def __init__(self, allowed_content_types: list[str]) -> None:
        """Initialize the AcceptHeaderValidation with a list of allowed content types."""
        self.allowed_content_types = allowed_content_types

    def validate(self, context: RequestContext) -> None:
        """Validate the presence of the 'Accept' header and check if it matches any of the allowed types."""
        if context.raw_message is None:
            error_message = 'Raw message is missing from the context.'
            self.logger.warning('Accept header validation failed: Raw message is missing')
            raise ValueError(error_message)

        if not hasattr(context.raw_message, 'headers') or not context.raw_message.headers:
            error_message = 'Raw message is missing headers.'
            self.logger.warning('Accept header validation failed: Raw message headers are missing')
            raise ValueError(error_message)


        accept_header = context.raw_message.headers.get('Accept')
        if not accept_header:
            self.logger.debug('Accept header validation skipped: No Accept header present')
            return

        accepted_types = [content_type.strip() for content_type in accept_header.split(',')]
        if not any(allowed_type in accepted_types for allowed_type in self.allowed_content_types):
            error_message = (
                f"The provided 'Accept' header '{accept_header}' does not match any "
                f"of the allowed types: {', '.join(self.allowed_content_types)}."
            )
            self.logger.warning("Accept header validation failed: '%s' not in allowed types %s",
                                accept_header, self.allowed_content_types)
            raise ValueError(error_message)

        self.logger.debug('Accept header validation successful: %s', accept_header)


class AuthorizationHeaderValidation(ValidationComponent, LoggerMixin):
    """Validate Authorization header for HTTP Basic Auth."""

    def validate(self, context: RequestContext) -> None:
        """Validate the presence and format of the 'Authorization' header and extract credentials."""
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

        if not auth_header.startswith('Basic '):
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
            raise ValueError(error_message) from e


class ClientCertificateValidation(ValidationComponent, LoggerMixin):
    """Check and optionally process the SSL client certificate from the request headers."""

    def validate(self, context: RequestContext) -> None:
        """Check for the presence of the 'HTTP_SSL_CLIENT_CERT' header and set the cert in the context if present."""
        if context.raw_message is None:
            error_message = 'Raw message is missing from the context.'
            self.logger.warning('Client certificate validation failed: Raw message is missing')
            raise ValueError(error_message)

        if not hasattr(context.raw_message, 'META') or not context.raw_message.META:
            self.logger.debug('Client certificate validation skipped: Raw message META is missing')
            return

        ssl_client_cert = context.raw_message.META.get('HTTP_SSL_CLIENT_CERT')

        if ssl_client_cert is None:
            self.logger.debug('Client certificate validation skipped: No HTTP_SSL_CLIENT_CERT present')
            return

        if not ssl_client_cert or not ssl_client_cert.strip():
            self.logger.debug('Client certificate validation skipped: HTTP_SSL_CLIENT_CERT is empty')
            return

        try:
            ssl_client_cert_unquoted = urllib.parse.unquote(ssl_client_cert)
            encoded_cert = ssl_client_cert_unquoted.encode('utf-8')
            client_certificate = x509.load_pem_x509_certificate(encoded_cert)
            context.client_certificate = client_certificate

            subject_cn = 'unknown'
            with contextlib.suppress(IndexError, AttributeError):
                cn_value = client_certificate.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
                subject_cn = cn_value if isinstance(cn_value, str) else cn_value.decode('utf-8')

            self.logger.debug(
                "Client certificate validation successful: Certificate loaded for subject '%s'", subject_cn)
        except Exception as e:
            error_message = f'Invalid HTTP_SSL_CLIENT_CERT header: {e}'
            self.logger.warning('Client certificate validation failed: %s', e)
            raise ValueError(error_message) from e


class IntermediateCertificatesValidation(ValidationComponent, LoggerMixin):
    """Validate and process intermediate CA certificates from the request headers."""

    def validate(self, context: RequestContext) -> None:
        """Extract and validate intermediate CA certificates from the 'SSL_CLIENT_CERT_CHAIN_*' headers."""
        if context.raw_message is None:
            error_message = 'Raw message is missing from the context.'
            self.logger.warning('Intermediate certificates validation failed: Raw message is missing')
            raise ValueError(error_message)

        intermediate_cas: list[x509.Certificate] = []

        for i in itertools.count():
            ca = context.raw_message.META.get(f'SSL_CLIENT_CERT_CHAIN_{i}')
            if not ca:
                break
            try:
                ca_cert = x509.load_pem_x509_certificate(ca.encode('utf-8'))
                intermediate_cas.append(ca_cert)
                self.logger.debug('Loaded intermediate certificate %d from SSL_CLIENT_CERT_CHAIN_%d', i, i)
            except Exception as e:
                error_message = f'Invalid SSL_CLIENT_CERT_CHAIN_{i} PEM: {e}'
                self.logger.warning(
                    'Intermediate certificates validation failed: Invalid certificate at position %d - %s', i, e)
                raise ValueError(error_message) from e

        context.client_intermediate_certificate = intermediate_cas if intermediate_cas else None

        if intermediate_cas:
            self.logger.debug(
                'Intermediate certificates validation successful: Loaded %d certificates', len(intermediate_cas))
        else:
            self.logger.debug('Intermediate certificates validation completed: No intermediate certificates found')


class ContentTransferEncodingValidation(ValidationComponent, LoggerMixin):
    """Validate the Content-Transfer-Encoding header and decode base64-encoded messages if required."""

    def validate(self, context: RequestContext) -> None:
        """Validates and processes requests with a Content-Transfer-Encoding header set to 'base64'."""
        if context.raw_message is None:
            error_message = 'Raw message is missing from the context.'
            self.logger.warning('Content transfer encoding validation failed: Raw message is missing')
            raise ValueError(error_message)

        if not hasattr(context.raw_message, 'headers') or not context.raw_message.headers:
            error_message = 'Raw message is missing headers.'
            self.logger.warning('Content transfer encoding validation failed: Raw message headers are missing')
            raise ValueError(error_message)

        if not hasattr(context.raw_message, 'body') or not context.raw_message.body:
            error_message = 'Raw message is missing body.'
            self.logger.warning('Content transfer encoding validation failed: Raw message body is missing')
            raise ValueError(error_message)

        encoding = context.raw_message.headers.get('Content-Transfer-Encoding', '').lower()
        encoding = context.raw_message.headers.get('Content-Transfer-Encoding', '').lower()
        if encoding == 'base64':
            try:
                decoded_message = base64.b64decode(context.raw_message.body)
                context.parsed_message = decoded_message
                self.logger.debug(
                    'Content transfer encoding validation successful: Decoded %d bytes to %d bytes',
                    len(context.raw_message.body), len(decoded_message))
            except Exception as e:
                error_message = 'Invalid base64 encoding in message.'
                self.logger.warning('Content transfer encoding validation failed: Invalid base64 encoding - %s', e)
                raise ValueError(error_message) from e
        else:
            self.logger.debug("Content transfer encoding validation skipped: Encoding is '%s', not 'base64'", encoding)


class CompositeValidation(ValidationComponent, LoggerMixin):
    """Composite validator to group multiple validators."""

    def __init__(self) -> None:
        """Initialize the composite validator with an empty list of components."""
        self.components: list[ValidationComponent] = []

    def add(self, component: ValidationComponent) -> None:
        """Add a new component to the composite."""
        self.components.append(component)

    def remove(self, component: ValidationComponent) -> None:
        """Remove a component from the composite."""
        if component in self.components:
            self.components.remove(component)
            self.logger.debug('Removed validation component: %s', component.__class__.__name__)
        else:
            error_message = f'Attempted to remove non-existent validation component: {component.__class__.__name__}'
            self.logger.warning(error_message)
            raise ValueError(error_message)

    def validate(self, context: RequestContext) -> None:
        """Validate all child components."""
        self.logger.debug('Starting composite validation with %d components', len(self.components))

        for i, component in enumerate(self.components):
            try:
                component.validate(context)
                self.logger.debug('Validation component %s passed', component.__class__.__name__)
            except ValueError as e:
                error_message = f'{component.__class__.__name__}: {e}'
                self.logger.warning('Validation component %s failed: %s', component.__class__.__name__, e)
                self.logger.exception(
                    'Composite validation failed at component %d/%d: %s',
                    i + 1, len(self.components), component.__class__.__name__)
                raise ValueError(error_message) from e
            except Exception as e:
                error_message = f'Unexpected error in {component.__class__.__name__}: {e}'
                self.logger.exception('Unexpected error in validation component %s', component.__class__.__name__)
                self.logger.exception(
                    'Composite validation failed at component %d/%d: %s',
                    i + 1, len(self.components), component.__class__.__name__)
                raise ValueError(error_message) from e

        self.logger.info('Composite validation successful. All %d components passed', len(self.components))


class CmpHttpRequestValidator(CompositeValidation):
    """Validator for CMP-specific HTTP requests."""

    def __init__(self) -> None:
        """Initialize the composite validator with the default set of validation components."""
        super().__init__()
        self.add(PayloadSizeValidation(max_payload_size=131072))
        self.add(ContentTypeValidation(expected_content_type='application/pkixcmp'))


class EstHttpRequestValidator(CompositeValidation):
    """Validator for EST-specific HTTP requests."""

    def __init__(self) -> None:
        """Initialize the composite validator with the default set of validation components."""
        super().__init__()
        self.add(PayloadSizeValidation(max_payload_size=65536))
        self.add(ContentTypeValidation(expected_content_type='application/pkcs10'))
        self.add(AcceptHeaderValidation(allowed_content_types=['application/pkcs7-mime','*/*']))
        self.add(AuthorizationHeaderValidation())
        self.add(ClientCertificateValidation())
        self.add(IntermediateCertificatesValidation())
        self.add(ContentTransferEncodingValidation())



