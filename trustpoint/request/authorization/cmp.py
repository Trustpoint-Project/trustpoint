"""Provides the 'CmpAuthorization' class using the Composite pattern for modular CMP authorization."""
from typing import Never

from pyasn1_modules.rfc4210 import PKIMessage  # type: ignore[import-untyped]

from request.request_context import BaseRequestContext, CmpBaseRequestContext
from trustpoint.logger import LoggerMixin

from .base import (
    AuthorizationComponent,
    CertificateProfileAuthorization,
    CompositeAuthorization,
    DevOwnerIDAuthorization,
    DomainScopeValidation,
    ProtocolAuthorization,
)


class CmpOperationAuthorization(AuthorizationComponent, LoggerMixin):
    """Ensures the request is authorized for the specified operation."""

    def __init__(self, allowed_operations: list[str]) -> None:
        """Initialize the authorization component with a list of allowed operations."""
        self.allowed_operations = allowed_operations

    def authorize(self, context: BaseRequestContext) -> None:
        """Authorize the request based on the operation type."""
        if not isinstance(context, CmpBaseRequestContext):
            exc_msg = 'CmpOperationAuthorization requires a CmpBaseRequestContext.'
            raise TypeError(exc_msg)

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


class CmpAuthorization(CompositeAuthorization):
    """Composite authorization handler for EST requests."""
    def __init__(self, allowed_operations: list[str] | None = None) -> None:
        """Initialize the composite authorization handler with the default set of components.

        Args:
            allowed_operations: List of allowed CMP operations. Defaults to ['cr', 'ir'] if not provided.
        """
        super().__init__()

        if allowed_operations is None:
            allowed_operations = ['certification', 'initialization']

        self.add(CertificateProfileAuthorization())
        self.add(DomainScopeValidation())
        self.add(DevOwnerIDAuthorization())
        self.add(ProtocolAuthorization(['cmp']))
        self.add(CmpOperationAuthorization(allowed_operations))
