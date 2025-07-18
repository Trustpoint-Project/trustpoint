"""Provides the `AuthorizationComponent` class for authorization logic."""
from abc import ABC, abstractmethod

from request.request_context import RequestContext
from trustpoint.logger import LoggerMixin


class AuthorizationComponent(ABC):
    """Abstract base class for authorization components."""

    @abstractmethod
    def authorize(self, context: RequestContext) -> None:
        """Execute authorization logic."""

class ProtocolAuthorization(AuthorizationComponent, LoggerMixin):
    """Ensures the request is under the correct protocol: CMP or EST."""

    def __init__(self, allowed_protocols: list[str]) -> None:
        """Initialize the authorization component with a list of allowed protocols."""
        self.allowed_protocols = allowed_protocols

    def authorize(self, context: RequestContext) -> None:
        """Authorize the request based on the protocol."""
        protocol = context.protocol

        if not protocol:
            error_message = 'Protocol information is missing. Authorization denied.'
            self.logger.warning("Protocol authorization failed: Protocol information is missing")
            raise ValueError(error_message)

        if protocol not in self.allowed_protocols:
            error_message = (
                f"Unauthorized protocol: '{protocol}'. "
                f"Allowed protocols: {', '.join(self.allowed_protocols)}."
            )
            self.logger.warning(
                f"Protocol authorization failed: {protocol} not in allowed protocols {self.allowed_protocols}")
            raise ValueError(error_message)

        self.logger.debug(f"Protocol authorization successful for protocol: {protocol}")

class OperationAuthorization(AuthorizationComponent, LoggerMixin):
    """Ensures the request is authorized for the specified operation."""

    def __init__(self, allowed_operations: list[str]) -> None:
        """Initialize the authorization component with a list of allowed operations."""
        self.allowed_operations = allowed_operations

    def authorize(self, context: RequestContext) -> None:
        """Authorize the request based on the operation type."""
        operation = context.operation

        if not operation:
            error_message = 'Operation information is missing. Authorization denied.'
            self.logger.warning("Operation authorization failed: Operation information is missing")
            raise ValueError(error_message)

        if operation not in self.allowed_operations:
            error_message = (
                f"Unauthorized operation: '{operation}'. "
                f"Allowed operations: {', '.join(self.allowed_operations)}."
            )
            self.logger.warning(f"Operation authorization failed: {operation} not in allowed operations {self.allowed_operations}")
            raise ValueError(error_message)

        self.logger.debug(f"Operation authorization successful for operation: {operation}")


class CertificateTemplateAuthorization(AuthorizationComponent, LoggerMixin):
    """Ensures the device is allowed to use the requested certificate template."""

    def __init__(self, allowed_templates: list[str]) -> None:
        """Initialize the authorization component with a list of allowed certificate templates."""
        self.allowed_templates = allowed_templates

    def authorize(self, context: RequestContext) -> None:
        """Authorize the request based on the certificate template."""
        requested_template = context.certificate_template

        if not requested_template:
            error_message = 'Certificate template is missing in the context. Authorization denied.'
            self.logger.warning("Certificate template authorization failed: Template information is missing")
            raise ValueError(error_message)

        if requested_template not in self.allowed_templates:
            error_message = (
                f"Unauthorized certificate template: '{requested_template}'. "
                f"Allowed templates: {', '.join(self.allowed_templates)}."
            )
            self.logger.warning(
                f"Certificate template authorization failed: {requested_template} not in allowed templates {self.allowed_templates}")
            raise ValueError(error_message)

        self.logger.debug(f"Certificate template authorization successful for template: {requested_template}")


class DomainScopeValidation(AuthorizationComponent, LoggerMixin):
    """Ensures the request is within the authorized domain."""

    def authorize(self, context: RequestContext) -> None:
        """Authorize the request based on the domain scope."""
        authenticated_device = context.device
        requested_domain = context.domain

        if not authenticated_device:
            error_message = 'Authenticated device is missing in the context. Authorization denied.'
            self.logger.warning("Domain scope validation failed: Authenticated device is missing")
            raise ValueError(error_message)

        if not requested_domain:
            error_message = 'Requested domain is missing in the context. Authorization denied.'
            self.logger.warning("Domain scope validation failed: Requested domain is missing")
            raise ValueError(error_message)

        device_domain = authenticated_device.domain

        if not device_domain or device_domain != requested_domain:
            error_message = (
                f"Unauthorized domain: '{requested_domain}'. "
                f"Device domain: '{device_domain}'."
            )
            self.logger.warning(
                f"Domain scope validation failed: Device domain {device_domain} "
                f"doesn't match requested domain {requested_domain}")
            raise ValueError(error_message)

        self.logger.debug(
            f"Domain scope validation successful: Device {authenticated_device.common_name} "
            f"authorized for domain {requested_domain}")


class ManualAuthorization(AuthorizationComponent, LoggerMixin):
    """Perform manual authorization override."""

    def authorize(self, context: RequestContext) -> None:
        """Authorize the request based on manual authorization."""
        self.logger.debug("Manual authorization check passed (placeholder implementation)")



class CompositeAuthorization(AuthorizationComponent, LoggerMixin):
    """Composite authorization handler for grouping and executing multiple authorization components."""

    def __init__(self) -> None:
        """Initialize the composite authorization handler with an empty list of components."""
        self.components: list[AuthorizationComponent] = []

    def add(self, component: AuthorizationComponent) -> None:
        """Add a new authorization component to the composite."""
        self.components.append(component)

    def remove(self, component: AuthorizationComponent) -> None:
        """Remove an authorization component from the composite."""
        if component in self.components:
            self.components.remove(component)
            self.logger.debug(f"Removed authorization component: {component.__class__.__name__}")
        else:
            error_message = f"Attempted to remove non-existent authorization component: {component.__class__.__name__}"
            self.logger.warning(error_message)
            raise ValueError(error_message)

    def authorize(self, context: RequestContext) -> None:
        """Iterate through all child authorization components and execute their authorization logic."""
        self.logger.debug(f"Starting composite authorization with {len(self.components)} components")

        for i, component in enumerate(self.components):
            try:
                component.authorize(context)
                self.logger.debug(f"Authorization component {component.__class__.__name__} passed")
            except ValueError as e:
                error_message = f"{component.__class__.__name__}: {e}"
                self.logger.warning(f"Authorization component {component.__class__.__name__} failed: {e}")
                self.logger.error(
                    f"Composite authorization failed at component {i + 1}/{len(self.components)}: {component.__class__.__name__}")
                raise ValueError(error_message) from e
            except Exception as e:
                error_message = f"Unexpected error in {component.__class__.__name__}: {e}"
                self.logger.error(f"Unexpected error in authorization component {component.__class__.__name__}: {e}")
                self.logger.error(
                    f"Composite authorization failed at component {i + 1}/{len(self.components)}: {component.__class__.__name__}")
                raise ValueError(error_message) from e

        self.logger.info(f"Composite authorization successful. All {len(self.components)} components passed")


class EstAuthorization(CompositeAuthorization):
    """Composite authorization handler for EST requests."""
    def __init__(self) -> None:
        """Initialize the composite authorization handler with the default set of components."""
        super().__init__()
        self.add(CertificateTemplateAuthorization(['tls-client']))
        self.add(DomainScopeValidation())
        self.add(ManualAuthorization())
        self.add(ProtocolAuthorization(['est']))
        self.add(OperationAuthorization(['simpleenroll']))
