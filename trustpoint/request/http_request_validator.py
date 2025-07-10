import base64
from abc import ABC, abstractmethod
from django.http import HttpRequest, HttpResponse
from cryptography import x509
import itertools

from request.request_context import RequestContext


class ValidationComponent(ABC):
    """Abstract base class to represent a component in composite validation."""

    @abstractmethod
    def validate(self, request: HttpRequest, context: RequestContext) -> None:
        """Execute validation logic and enrich context."""
        pass

class PayloadSizeValidation(ValidationComponent):
    """Validate payload size."""

    def __init__(self, max_payload_size: int) -> None:
        self.max_payload_size = max_payload_size

    def validate(self, request: HttpRequest, context: RequestContext) -> None:
        raw_message = context.get("raw_message") or request.read()
        if not context.has("raw_message"):
            context.set("raw_message", raw_message)

        if len(raw_message) > self.max_payload_size:
            raise ValueError(f"Payload size exceeds {self.max_payload_size} bytes.")

        context.set("payload_size", len(raw_message))


class ContentTypeValidation(ValidationComponent):
    """Validate request content type."""

    def __init__(self, expected_content_type: str) -> None:
        self.expected_content_type = expected_content_type

    def validate(self, request: HttpRequest, context: RequestContext) -> None:
        content_type = request.headers.get("Content-Type")
        if not content_type:
            raise ValueError("Missing 'Content-Type' header.")
        if content_type != self.expected_content_type:
            raise ValueError(
                f"Invalid content type: {content_type}. Expected: {self.expected_content_type}."
            )

        context.set("content_type", content_type)


class AcceptHeaderValidation(ValidationComponent):
    """Validate the Accept header."""

    def __init__(self, allowed_content_types: list[str]) -> None:
        self.allowed_content_types = allowed_content_types

    def validate(self, request: HttpRequest, context: RequestContext) -> None:
        accept_header = request.headers.get("Accept")
        if not accept_header:
            raise ValueError("The 'Accept' header is missing.")

        accepted_types = [content_type.strip() for content_type in accept_header.split(",")]
        if not any(
            allowed_type in accepted_types for allowed_type in self.allowed_content_types
        ):
            raise ValueError(
                f"The provided 'Accept' header '{accept_header}' does not match any of the "
                f"allowed types: {', '.join(self.allowed_content_types)}."
            )

        context.set("accept_header", accept_header)

class AuthorizationHeaderValidation(ValidationComponent):
    """Validate Authorization header for HTTP Basic Auth."""

    def validate(self, request: HttpRequest, context: RequestContext) -> None:
        """Validate the presence and format of the 'Authorization' header and extract credentials."""
        auth_header = request.headers.get("Authorization")
        if not auth_header or not auth_header.startswith("Basic "):
            return

        try:
            credentials = base64.b64decode(auth_header.split(" ", 1)[1].strip()).decode("utf-8")
            username, password = credentials.split(":", 1)

            context.set("username", username)
            context.set("password", password)
        except Exception:
            raise ValueError("Malformed 'Authorization' header credentials.")

class ClientCertificateValidation(ValidationComponent):
    """Check and optionally process the SSL client certificate from the request headers."""

    def validate(self, request: HttpRequest, context: RequestContext) -> None:
        """Check for the presence of the 'SSL_CLIENT_CERT' header and set the certificate in the context if present."""
        cert_data = request.headers.get("SSL_CLIENT_CERT")

        try:
            client_cert = x509.load_pem_x509_certificate(cert_data.encode('utf-8'))
        except Exception as e:
            error_message = f'Invalid SSL_CLIENT_CERT header: {e}'
            raise ValueError(error_message) from e

        if client_cert:
            context.set("client_certificate", client_cert)


class IntermediateCertificatesValidation(ValidationComponent):
    """Validate and process intermediate CA certificates from the request headers."""

    def validate(self, request: HttpRequest, context: RequestContext) -> None:
        """Extract and validate intermediate CA certificates from the 'SSL_CLIENT_CERT_CHAIN_*' headers."""
        intermediate_cas = []

        for i in itertools.count():
            ca = request.META.get(f"SSL_CLIENT_CERT_CHAIN_{i}")
            if not ca:
                break
            try:
                ca_cert = x509.load_pem_x509_certificate(ca.encode("utf-8"))
            except Exception as e:
                error_message = f"Invalid SSL_CLIENT_CERT_CHAIN_{i} PEM: {e}"
                raise ValueError(error_message) from e

            intermediate_cas.append(ca_cert)

        context.set("intermediate_certificates", intermediate_cas)


class CompositeValidation(ValidationComponent):
    """Composite validator to group multiple validators."""

    def __init__(self) -> None:
        self.components: list[ValidationComponent] = []

    def add(self, component: ValidationComponent) -> None:
        """Add a new component to the composite."""
        self.components.append(component)

    def remove(self, component: ValidationComponent) -> None:
        """Remove a component from the composite."""
        self.components.remove(component)

    def validate(self, request: HttpRequest, context: RequestContext) -> None:
        """Validate all child components."""
        for component in self.components:
            component.validate(request, context)



class CmpHttpRequestValidator(CompositeValidation):
    """Validator for CMP-specific HTTP requests."""

    def __init__(self) -> None:
        super().__init__()
        self.add(PayloadSizeValidation(max_payload_size=131072))
        self.add(ContentTypeValidation(expected_content_type="application/pkixcmp"))


class EstHttpRequestValidator(CompositeValidation):
    """Validator for EST-specific HTTP requests."""

    def __init__(self) -> None:
        super().__init__()
        self.add(PayloadSizeValidation(max_payload_size=65536))
        self.add(ContentTypeValidation(expected_content_type="application/pkcs7-mime"))
        self.add(AcceptHeaderValidation(allowed_content_types=["application/pkcs7-mime", "application/pkcs7-response"]))
        self.add(AuthorizationHeaderValidation())
        self.add(ClientCertificateValidation())
        self.add(IntermediateCertificatesValidation())


