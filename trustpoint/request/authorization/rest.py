"""Provides the 'RestAuthorization' class using the Composite pattern for modular REST authorization."""

from request.request_context import BaseRequestContext, RestBaseRequestContext
from trustpoint.logger import LoggerMixin

from .base import (
    AuthorizationComponent,
    CertificateProfileAuthorization,
    CompositeAuthorization,
    DomainScopeValidation,
    OnboardingDomainCredentialAuthorization,
    ProtocolAuthorization,
    SecurityConfigAuthorization,
)


class RestOperationAuthorization(AuthorizationComponent, LoggerMixin):
    """Ensures the REST request is authorized for the specified operation."""

    def __init__(self, allowed_operations: list[str]) -> None:
        """Initialize the authorization component with a list of allowed operations."""
        self.allowed_operations = allowed_operations

    def authorize(self, context: BaseRequestContext) -> None:
        """Authorize the request based on the operation type."""
        if not isinstance(context, RestBaseRequestContext):
            exc_msg = 'RestOperationAuthorization requires a RestBaseRequestContext.'
            raise TypeError(exc_msg)

        operation = context.operation

        if not operation:
            error_message = 'Operation information is missing. Authorization denied.'
            self.logger.warning('REST operation authorization failed: Operation information is missing')
            raise ValueError(error_message)

        if operation not in self.allowed_operations:
            error_message = (
                f"Unauthorized operation: '{operation}'. "
                f"Allowed operations: {', '.join(self.allowed_operations)}."
            )
            self.logger.warning(
                'REST operation authorization failed: %s not in allowed operations %s',
                operation, self.allowed_operations
            )
            raise ValueError(error_message)

        self.logger.debug('REST operation authorization successful for operation: %s', operation)


class RestAuthorization(CompositeAuthorization):
    """Composite authorization handler for REST requests."""

    def __init__(self, allowed_operations: list[str] | None = None) -> None:
        """Initialize the composite authorization handler with the default set of components.

        Args:
            allowed_operations: List of allowed REST operations. Defaults to ['enroll', 'reenroll'].
        """
        super().__init__()

        if allowed_operations is None:
            allowed_operations = ['enroll', 'reenroll']

        self.add(DomainScopeValidation())
        self.add(CertificateProfileAuthorization())
        self.add(OnboardingDomainCredentialAuthorization())
        self.add(ProtocolAuthorization(['rest']))
        self.add(RestOperationAuthorization(allowed_operations))
        self.add(SecurityConfigAuthorization())
