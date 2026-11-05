# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Provides the 'ScepAuthorization' class using the Composite pattern for modular SCEP authorization."""

from request.request_context import BaseRequestContext, ScepBaseRequestContext
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


class ScepOperationAuthorization(AuthorizationComponent, LoggerMixin):
    """Ensures the SCEP message type is one of the supported operations."""

    def __init__(self, allowed_operations: list[str]) -> None:
        """Initialize with the allowed operation names."""
        self.allowed_operations = allowed_operations

    def authorize(self, context: BaseRequestContext) -> None:
        """Reject any operation that is not explicitly allowed."""
        if not isinstance(context, ScepBaseRequestContext):
            exc_msg = 'ScepOperationAuthorization requires a ScepBaseRequestContext.'
            raise TypeError(exc_msg)
        if context.operation not in self.allowed_operations:
            exc_msg = f"Unauthorized SCEP operation: '{context.operation}'."
            self.logger.warning('SCEP operation authorization failed: %s', context.operation)
            raise ValueError(exc_msg)


class ScepAuthorization(CompositeAuthorization):
    """Composite authorization handler for SCEP requests."""

    def __init__(self, allowed_operations: list[str] | None = None) -> None:
        """Initialize with the default component set; PKCSReq and RenewalReq are the supported operations."""
        super().__init__()
        self.add(DomainScopeValidation())
        self.add(CertificateProfileAuthorization())
        self.add(OnboardingDomainCredentialAuthorization())
        self.add(ProtocolAuthorization(['scep']))
        self.add(ScepOperationAuthorization(allowed_operations or ['pkcsreq', 'renewalreq']))
        self.add(SecurityConfigAuthorization())
