"""Provides the 'EstAuthentication' class using the Composite pattern for modular EST authorization."""

from request.request_context import BaseRequestContext, EstBaseRequestContext
from trustpoint.logger import LoggerMixin

from .base import (
    AuthorizationComponent,
    CertificateProfileAuthorization,
    CompositeAuthorization,
    DomainScopeValidation,
    ProtocolAuthorization,
)


class EstOperationAuthorization(AuthorizationComponent, LoggerMixin):
    """Ensures the request is authorized for the specified operation."""

    def __init__(self, allowed_operations: list[str]) -> None:
        """Initialize the authorization component with a list of allowed operations."""
        self.allowed_operations = allowed_operations

    def authorize(self, context: BaseRequestContext) -> None:
        """Authorize the request based on the operation type."""
        if not isinstance(context, EstBaseRequestContext):
            exc_msg = 'EstOperationAuthorization requires an EstBaseRequestContext.'
            raise TypeError(exc_msg)

        operation = context.operation

        if not operation:
            error_message = 'Operation information is missing. Authorization denied.'
            self.logger.warning('Operation authorization failed: Operation information is missing')
            raise ValueError(error_message)

        if operation not in self.allowed_operations:
            error_message = (
                f"Unauthorized operation: '{operation}'. Allowed operations: {', '.join(self.allowed_operations)}."
            )
            self.logger.warning(
                'Operation authorization failed: %s not in allowed operations %s', operation, self.allowed_operations
            )
            raise ValueError(error_message)

        self.logger.debug('Operation authorization successful for operation: %s', operation)


class EstAuthorization(CompositeAuthorization):
    """Composite authorization handler for EST requests."""

    def __init__(self, allowed_operations: list[str] | None = None) -> None:
        """Initialize the composite authorization handler with the default set of components.

        Args:
            allowed_operations: List of allowed CMP operations. Defaults to ['cr', 'ir'] if not provided.
        """
        super().__init__()

        if allowed_operations is None:
            allowed_operations = ['simpleenroll', 'simplereenroll']

        self.add(DomainScopeValidation())
        self.add(CertificateProfileAuthorization())
        self.add(ProtocolAuthorization(['est']))
        self.add(EstOperationAuthorization(allowed_operations))
