"""Provides the `HttpRequestValidator` class for validating HTTP requests."""
import base64
import itertools
from abc import ABC, abstractmethod

from cryptography import x509

from request.request_context import RequestContext


class ValidationComponent(ABC):
    """Abstract base class to represent a component in composite validation."""

    @abstractmethod
    def validate(self, context: RequestContext) -> None:
        """Execute validation logic and enrich context."""

class PayloadSizeValidation(ValidationComponent):
    """Validate payload size."""

    def __init__(self, max_payload_size: int) -> None:
        """Initialize the PayloadSizeValidation with the maximum allowed payload size."""
        self.max_payload_size = max_payload_size

    def validate(self, context: RequestContext) -> None:
        """Validate the payload size against the maximum allowed size."""
        if context.raw_message is None:
            error_message = 'Raw message is missing from the context.'
            raise ValueError(error_message)

        if not hasattr(context.raw_message, 'body') or not context.raw_message.body:
            error_message = 'Raw message is missing body.'
            raise ValueError(error_message)

        if len(context.raw_message.body) > self.max_payload_size:
            error_message = f'Payload size exceeds maximum allowed size of {self.max_payload_size} bytes.'
            raise ValueError(error_message)


class ContentTypeValidation(ValidationComponent):
    """Validate request content type."""

    def __init__(self, expected_content_type: str) -> None:
        """Initialize the ContentTypeValidation with the expected content type."""
        self.expected_content_type = expected_content_type

    def validate(self, context: RequestContext) -> None:
        """Validate the presence of the 'Content-Type' header and check if it matches the expected type."""
        if context.raw_message is None:
            error_message = 'Raw message is missing from the context.'
            raise ValueError(error_message)

        if not hasattr(context.raw_message, 'headers') or not context.raw_message.headers:
            error_message = 'Raw message is missing headers.'
            raise ValueError(error_message)

        content_type = context.raw_message.headers.get('Content-Type')
        if not content_type:
            error_message = "Missing 'Content-Type' header."
            raise ValueError(error_message)
        if content_type != self.expected_content_type:
            error_message = (f"Invalid 'Content-Type' header '{content_type}'. "
                             f"Expected '{self.expected_content_type}'.")
            raise ValueError(error_message)

class AcceptHeaderValidation(ValidationComponent):
    """Validate the Accept header."""
    # TODO(FHK): not mandatory # noqa: FIX002

    def __init__(self, allowed_content_types: list[str]) -> None:
        """Initialize the AcceptHeaderValidation with a list of allowed content types."""
        self.allowed_content_types = allowed_content_types

    def validate(self, context: RequestContext) -> None:
        """Validate the presence of the 'Accept' header and check if it matches any of the allowed types."""
        if context.raw_message is None:
            error_message = 'Raw message is missing from the context.'
            raise ValueError(error_message)

        if not hasattr(context.raw_message, 'headers') or not context.raw_message.headers:
            error_message = 'Raw message is missing headers.'
            raise ValueError(error_message)

        accept_header = context.raw_message.headers.get('Accept')
        if not accept_header:
            error_message = "The 'Accept' header is missing."
            raise ValueError(error_message)

        accepted_types = [content_type.strip() for content_type in accept_header.split(',')]
        if not any(
            allowed_type in accepted_types for allowed_type in self.allowed_content_types
        ):
            error_message = (f"The provided 'Accept' header '{accept_header}' does not match any "
                             f"of the allowed types: {', '.join(self.allowed_content_types)}.")
            raise ValueError(error_message)

class AuthorizationHeaderValidation(ValidationComponent):
    """Validate Authorization header for HTTP Basic Auth."""

    def validate(self, context: RequestContext) -> None:
        """Validate the presence and format of the 'Authorization' header and extract credentials."""
        if context.raw_message is None:
            error_message = 'Raw message is missing from the context.'
            raise ValueError(error_message)

        if not hasattr(context.raw_message, 'headers') or not context.raw_message.headers:
            error_message = 'Raw message is missing headers.'
            raise ValueError(error_message)

        auth_header = context.raw_message.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Basic '):
            return

        try:
            credentials = base64.b64decode(auth_header.split(' ', 1)[1].strip()).decode('utf-8')
            est_username, est_password = credentials.split(':', 1)

            context.est_username = est_username
            context.est_password = est_password
        except Exception as e:
            error_message = "Malformed 'Authorization' header credentials."
            raise ValueError(error_message) from e

class ClientCertificateValidation(ValidationComponent):
    """Check and optionally process the SSL client certificate from the request headers."""

    def validate(self, context: RequestContext) -> None:
        """Check for the presence of the 'SSL_CLIENT_CERT' header and set the certificate in the context if present."""
        if context.raw_message is None:
            error_message = 'Raw message is missing from the context.'
            raise ValueError(error_message)

        if not hasattr(context.raw_message, 'headers') or not context.raw_message.headers:
            error_message = 'Raw message is missing headers.'
            raise ValueError(error_message)

        ssl_client_cert = context.raw_message.headers.get('SSL_CLIENT_CERT')

        if ssl_client_cert is None:
            return

        encoded_cert = ssl_client_cert.encode()

        try:
            client_certificate = x509.load_pem_x509_certificate(encoded_cert)
        except Exception as e:
            error_message = f'Invalid SSL_CLIENT_CERT header: {e}'
            raise ValueError(error_message) from e

        if client_certificate:
            context.client_certificate = client_certificate


class IntermediateCertificatesValidation(ValidationComponent):
    """Validate and process intermediate CA certificates from the request headers."""

    def validate(self, context: RequestContext) -> None:
        """Extract and validate intermediate CA certificates from the 'SSL_CLIENT_CERT_CHAIN_*' headers."""
        intermediate_cas: list[x509.Certificate] = []

        if context.raw_message is None:
            error_message = 'Raw message is missing from the context.'
            raise ValueError(error_message)

        for i in itertools.count():
            ca = context.raw_message.META.get(f'SSL_CLIENT_CERT_CHAIN_{i}')
            if not ca:
                break
            try:
                ca_cert = x509.load_pem_x509_certificate(ca.encode('utf-8'))
            except Exception as e:
                error_message = f'Invalid SSL_CLIENT_CERT_CHAIN_{i} PEM: {e}'
                raise ValueError(error_message) from e

            intermediate_cas.append(ca_cert)

        context.client_intermediate_certificate = intermediate_cas

class ContentTransferEncodingValidation(ValidationComponent):
    """Validate the Content-Transfer-Encoding header and decode base64-encoded messages if required."""

    def validate(self, context: RequestContext) -> None:
        """Validates and processes requests with a Content-Transfer-Encoding header set to 'base64'."""
        if context.raw_message is None:
            error_message = 'Raw message is missing from the context.'
            raise ValueError(error_message)

        if not hasattr(context.raw_message, 'headers') or not context.raw_message.headers:
            error_message = 'Raw message is missing headers.'
            raise ValueError(error_message)

        if not hasattr(context.raw_message, 'body') or not context.raw_message.body:
            error_message = 'Raw message is missing body.'
            raise ValueError(error_message)

        encoding = context.raw_message.headers.get('Content-Transfer-Encoding', '').lower()
        if encoding == 'base64':
            try:
                decoded_message = base64.b64decode(context.raw_message.body)
            except Exception as e:
                error_message = 'Invalid base64 encoding in message.'
                raise ValueError(error_message) from e

            context.parsed_message = decoded_message


class CompositeValidation(ValidationComponent):
    """Composite validator to group multiple validators."""

    def __init__(self) -> None:
        """Initialize the composite validator with an empty list of components."""
        self.components: list[ValidationComponent] = []

    def add(self, component: ValidationComponent) -> None:
        """Add a new component to the composite."""
        self.components.append(component)

    def remove(self, component: ValidationComponent) -> None:
        """Remove a component from the composite."""
        self.components.remove(component)

    def validate(self, context: RequestContext) -> None:
        """Validate all child components."""
        for component in self.components:
            component.validate(context)



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
        self.add(ContentTypeValidation(expected_content_type='application/pkcs7-mime'))
        self.add(AcceptHeaderValidation(allowed_content_types=['application/pkcs7-mime']))
        self.add(AuthorizationHeaderValidation())
        self.add(ClientCertificateValidation())
        self.add(IntermediateCertificatesValidation())
        self.add(ContentTransferEncodingValidation())



