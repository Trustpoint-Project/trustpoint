"""Provides the `AuthorizationComponent` class for authorization logic."""
from abc import ABC, abstractmethod
from typing import Never

from pyasn1_modules.rfc4210 import PKIMessage  # type: ignore[import-untyped]

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
            self.logger.warning('Protocol authorization failed: Protocol information is missing')
            raise ValueError(error_message)

        if protocol not in self.allowed_protocols:
            error_message = (
                f"Unauthorized protocol: '{protocol}'. "
                f"Allowed protocols: {', '.join(self.allowed_protocols)}."
            )
            self.logger.warning(
                'Protocol authorization failed: %(protocol)s not in allowed protocols %(allowed_protocols)s',
                extra={'protocol': protocol, 'allowed_protocols': self.allowed_protocols})
            raise ValueError(error_message)

        self.logger.debug('Protocol authorization successful for protocol: %(protocol)s',
                          extra={'protocol': protocol})

class EstOperationAuthorization(AuthorizationComponent, LoggerMixin):
    """Ensures the request is authorized for the specified operation."""

    def __init__(self, allowed_operations: list[str]) -> None:
        """Initialize the authorization component with a list of allowed operations."""
        self.allowed_operations = allowed_operations

    def authorize(self, context: RequestContext) -> None:
        """Authorize the request based on the operation type."""
        operation = context.operation

        if not operation:
            error_message = 'Operation information is missing. Authorization denied.'
            self.logger.warning('Operation authorization failed: Operation information is missing')
            raise ValueError(error_message)

        if operation not in self.allowed_operations:
            error_message = (
                f"Unauthorized operation: '{operation}'. "
                f"Allowed operations: {', '.join(self.allowed_operations)}."
            )
            self.logger.warning(
                'Operation authorization failed: %(operation)s not in allowed operations %(allowed_operations)s',
                extra={'operation': operation, 'allowed_operations': self.allowed_operations})
            raise ValueError(error_message)

        self.logger.debug('Operation authorization successful for operation: %(operation)s',
                          extra={'operation': operation})

class CmpOperationAuthorization(AuthorizationComponent, LoggerMixin):
    """Ensures the request is authorized for the specified operation."""

    def __init__(self, allowed_operations: list[str]) -> None:
        """Initialize the authorization component with a list of allowed operations."""
        self.allowed_operations = allowed_operations

    def authorize(self, context: RequestContext) -> None:
        """Authorize the request based on the operation type."""
        operation = context.operation

        if not operation:
            error_message = 'Operation information is missing. Authorization denied.'
            self.logger.warning('Operation authorization failed: Operation information is missing')
            raise ValueError(error_message)

        if operation not in self.allowed_operations:
            error_message = (
                f"Unauthorized operation: '{operation}'. "
                f"Allowed operations: {', '.join(self.allowed_operations)}."
            )
            self.logger.warning(
                'Operation authorization failed: %(operation)s not in allowed operations %(allowed_operations)s',
                extra={'operation': operation, 'allowed_operations': self.allowed_operations})
            raise ValueError(error_message)

        if not isinstance(context.parsed_message, PKIMessage):
            error_message = 'Parsed message is missing. Authorization denied.'
            self.logger.warning('Operation authorization failed: Parsed message is missing or invalid')
            self._raise_value_error(error_message)

        body_type = context.parsed_message['body'].getName()

        if context.operation == 'initialization' and body_type == 'ir':
            self._authorize_asn1_body(context.parsed_message, 'ir')
            self.logger.info('CMP body type validation successful: IR body extracted')
        elif context.operation == 'certification' and body_type == 'cr':
            self._authorize_asn1_body(context.parsed_message, 'cr')
            self.logger.info('CMP body type validation successful: CR body extracted')
        else:
            err_msg = f'Expected CMP {context.operation} body, but got CMP {body_type.upper()} body.'
            raise ValueError(err_msg)

        self.logger.debug('Operation authorization successful for operation: %(operation)s',
                          extra={'operation': operation})
    
    def _raise_value_error(self, message: str) -> Never:
        """Raise a ValueError with the given message."""
        raise ValueError(message)

    def _authorize_asn1_body(self, serialized_pyasn1_message: PKIMessage, expected_body_type: str) -> None:
        """Extract and validate the specified body type from the CMP message.

        Args:
            serialized_pyasn1_message: The CMP message to extract the body from.
            expected_body_type: The expected body type ('cr' or 'ir').
        """
        message_body_name = serialized_pyasn1_message['body'].getName()
        if message_body_name != expected_body_type:
            err_msg = f'Expected CMP {expected_body_type.upper()} body, but got CMP {message_body_name.upper()} body.'
            raise ValueError(err_msg)

        if serialized_pyasn1_message['body'].getName() != expected_body_type:
            err_msg = f'not {expected_body_type} message'
            raise ValueError(err_msg)


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
            self.logger.warning('Certificate template authorization failed: Template information is missing')
            raise ValueError(error_message)

        if requested_template not in self.allowed_templates:
            error_message = (
                f"Unauthorized certificate template: '{requested_template}'. "
                f"Allowed templates: {', '.join(self.allowed_templates)}."
            )
            self.logger.warning(
                (
                    'Certificate template authorization failed: %(requested_template)s not in '
                    'allowed templates %(allowed_templates)s'
                ),
                extra={'requested_template': requested_template, 'allowed_templates': self.allowed_templates})
            raise ValueError(error_message)

        self.logger.debug(
            'Certificate template authorization successful for template: %(template)s',
            extra={'template': requested_template}
        )


class DomainScopeValidation(AuthorizationComponent, LoggerMixin):
    """Ensures the request is within the authorized domain."""

    def authorize(self, context: RequestContext) -> None:
        """Authorize the request based on the domain scope."""
        authenticated_device = context.device
        requested_domain = context.domain

        if not authenticated_device:
            error_message = 'Authenticated device is missing in the context. Authorization denied.'
            self.logger.warning('Domain scope validation failed: Authenticated device is missing')
            raise ValueError(error_message)

        if not requested_domain:
            error_message = 'Requested domain is missing in the context. Authorization denied.'
            self.logger.warning('Domain scope validation failed: Requested domain is missing')
            raise ValueError(error_message)

        device_domain = authenticated_device.domain

        if not device_domain or device_domain != requested_domain:
            error_message = (
                f"Unauthorized domain: '{requested_domain}'. "
                f"Device domain: '{device_domain}'."
            )
            self.logger.warning(
                "Domain scope validation failed: Device domain %(device_domain)s "
                "doesn't match requested domain %(requested_domain)s",
                extra={'device_domain': device_domain, 'requested_domain': requested_domain})
            raise ValueError(error_message)

        self.logger.debug(
            'Domain scope validation successful: Device %(device_name)s authorized for domain %(domain_name)s',
            extra={'device_name': authenticated_device.common_name, 'domain_name': requested_domain})


class ManualAuthorization(AuthorizationComponent, LoggerMixin):
    """Perform manual authorization override."""

    def authorize(self, context: RequestContext) -> None:
        """Authorize the request based on manual authorization."""
        del context
        self.logger.debug('Manual authorization check passed (placeholder implementation)')



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
            self.logger.debug('Removed authorization component', extra={'component_name': component.__class__.__name__})
        else:
            error_message = f'Attempted to remove non-existent authorization component: {component.__class__.__name__}'
            self.logger.warning(error_message)
            raise ValueError(error_message)

    def authorize(self, context: RequestContext) -> None:
        """Iterate through all child authorization components and execute their authorization logic."""
        self.logger.debug('Starting composite authorization with %(component_count)d components',
                          extra={'component_count': len(self.components)})

        for i, component in enumerate(self.components):
            try:
                component.authorize(context)
                self.logger.debug('Authorization component passed',
                                  extra={'component_name': component.__class__.__name__})
            except ValueError as e:
                error_message = f'{component.__class__.__name__}: {e}'
                self.logger.warning('Authorization component failed',
                                    extra={'component_name': component.__class__.__name__, 'error_message': str(e)})
                self.logger.exception(
                    (
                        'Composite authorization failed at component '
                        '%(component_index)d/%(total_components)d: %(component_name)s'
                    ),
                    extra={'component_index': i + 1,
                           'total_components': len(self.components),
                           'component_name': component.__class__.__name__})
                raise ValueError(error_message) from e
            except Exception as e:
                error_message = f'Unexpected error in {component.__class__.__name__}: {e}'
                self.logger.exception(
                    'Unexpected error in authorization component %(component_name)s: %(error_message)s',
                    extra={'component_name': component.__class__.__name__, 'error_message': str(e)}
                )
                self.logger.exception(
                    (
                    'Composite authorization failed at component ',
                    '%(component_index)d/%(total_components)d: %(component_name)s',
                    ),
                    extra={'component_index': i + 1,
                           'total_components': len(self.components),
                           'component_name': component.__class__.__name__})
                raise ValueError(error_message) from e

        self.logger.info(
            'Composite authorization successful. All %(component_count)d components passed',
            extra={'component_count': len(self.components)}
        )


class EstAuthorization(CompositeAuthorization):
    """Composite authorization handler for EST requests."""
    def __init__(self, allowed_templates: list[str] | None = None, allowed_operations: list[str] | None = None) -> None:
        """Initialize the composite authorization handler with the default set of components.

        Args:
            allowed_templates: List of allowed certificate templates. Defaults to ['tls-client'] if not provided.
            allowed_operations: List of allowed CMP operations. Defaults to ['cr', 'ir'] if not provided.
        """
        super().__init__()

        if allowed_templates is None:
            allowed_templates = ['tls-client']

        if allowed_operations is None:
            allowed_operations = ['simpleenroll', 'simplereenroll']

        self.add(CertificateTemplateAuthorization(allowed_templates))
        self.add(DomainScopeValidation())
        self.add(ManualAuthorization())
        self.add(ProtocolAuthorization(['est']))
        self.add(EstOperationAuthorization(allowed_operations))

class CmpAuthorization(CompositeAuthorization):
    """Composite authorization handler for EST requests."""
    def __init__(self, allowed_templates: list[str] | None = None, allowed_operations: list[str] | None = None) -> None:
        """Initialize the composite authorization handler with the default set of components.

        Args:
            allowed_templates: List of allowed certificate templates. Defaults to ['tls-client'] if not provided.
            allowed_operations: List of allowed CMP operations. Defaults to ['cr', 'ir'] if not provided.
        """
        super().__init__()

        if allowed_templates is None:
            allowed_templates = ['tls-client']

        if allowed_operations is None:
            allowed_operations = ['certification', 'initialization']

        self.add(CertificateTemplateAuthorization(allowed_templates))
        self.add(DomainScopeValidation())
        self.add(ManualAuthorization())
        self.add(ProtocolAuthorization(['cmp']))
        self.add(CmpOperationAuthorization(allowed_operations))
