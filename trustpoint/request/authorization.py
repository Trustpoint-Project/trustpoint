"""Provides the `AuthorizationComponent` class for authorization logic."""
from abc import ABC, abstractmethod

from request.request_context import RequestContext


class AuthorizationComponent(ABC):
    """Abstract base class for authorization components."""

    @abstractmethod
    def authorize(self, context: RequestContext) -> None:
        """Execute authorization logic."""

class ProtocolAuthorization(AuthorizationComponent):
    """Ensures the request is under the correct protocol: CMP or EST."""

    def __init__(self, allowed_protocols: list[str]) -> None:
        """Initialize the authorization component with a list of allowed protocols."""
        self.allowed_protocols = allowed_protocols

    def authorize(self, context: RequestContext) -> None:
        """Authorize the request based on the protocol."""
        protocol = context.protocol

        if not protocol:
            error_message = 'Protocol information is missing. Authorization denied.'
            raise ValueError(error_message)

        if protocol not in self.allowed_protocols:
            error_message = (f"Unauthorized protocol: '{protocol}'. "
                             f"Allowed protocols: {', '.join(self.allowed_protocols)}.")
            raise ValueError(error_message)

class OperationAuthorization(AuthorizationComponent):
    """Ensures the request is authorized for the specified operation."""

    def __init__(self, allowed_operations: list[str]) -> None:
        """Initialize the authorization component with a list of allowed operations."""
        self.allowed_operations = allowed_operations

    def authorize(self, context: RequestContext) -> None:
        """Authorize the request based on the operation type."""
        operation = context.operation

        if not operation:
            error_message = 'Operation information is missing. Authorization denied.'
            raise ValueError(error_message)

        if operation not in self.allowed_operations:
            error_message = (f"Unauthorized operation: '{operation}'. Allowed operations: ")
            raise ValueError(error_message)

class CertificateTemplateAuthorization(AuthorizationComponent):
    """Ensures the device is allowed to use the requested certificate template."""

    def __init__(self, allowed_templates: list[str]) -> None:
        """Initialize the authorization component with a list of allowed certificate templates."""
        self.allowed_templates = allowed_templates

    def authorize(self, context: RequestContext) -> None:
        """Authorize the request based on the certificate template."""
        requested_template = context.certificate_template

        if not requested_template:
            error_message = 'Certificate template is missing in the context. Authorization denied.'
            raise ValueError(error_message)

        if requested_template not in self.allowed_templates:
            error_message = (f"Unauthorized certificate template: '{requested_template}'. "
                             f"Allowed templates: {', '.join(self.allowed_templates)}.")
            raise ValueError(error_message)


class DomainScopeValidation(AuthorizationComponent):
    """Ensures the request is within the authorized domain."""

    def authorize(self, context: RequestContext) -> None:
        """Authorize the request based on the domain scope."""
        authenticated_device = context.device
        requested_domain = context.domain

        if not authenticated_device:
            error_message = 'Authenticated device is missing in the context. Authorization denied.'
            raise ValueError(error_message)
        if not requested_domain:
            error_message = 'Requested domain is missing in the context. Authorization denied.'
            raise ValueError(error_message)

        device_domain = authenticated_device.domain

        if not device_domain or device_domain != requested_domain:
            error_message = f"Unauthorized domain: '{requested_domain}'. Device domain: '{device_domain}'."
            raise ValueError(error_message)


class ManualAuthorization(AuthorizationComponent):
    """Perform manual authorization override."""

    def authorize(self, context: RequestContext) -> None:
        """Authorize the request based on manual authorization."""



class CompositeAuthorization(AuthorizationComponent):
    """Composite authorization handler for grouping and executing multiple authorization components."""

    def __init__(self) -> None:
        """Initialize the composite authorization handler with an empty list of components."""
        self.components: list[AuthorizationComponent] = []

    def add(self, component: AuthorizationComponent) -> None:
        """Add a new authorization component to the composite."""
        self.components.append(component)

    def remove(self, component: AuthorizationComponent) -> None:
        """Remove an authorization component from the composite."""
        self.components.remove(component)

    def authorize(self, context: RequestContext) -> None:
        """Iterate through all child authorization components and execute their authorization logic."""
        for component in self.components:
            component.authorize(context)


class EstAuthorization(CompositeAuthorization):
    """Composite authorization handler for EST requests."""
    def __init__(self) -> None:
        """Initialize the composite authorization handler with the default set of components."""
        super().__init__()
        self.add(CertificateTemplateAuthorization(['tls-clientt']))
        self.add(DomainScopeValidation())
        self.add(ManualAuthorization())
        self.add(ProtocolAuthorization(['est']))
        self.add(OperationAuthorization(['simpleenroll']))
