# Copyright (c) 2025 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Provides the 'EstAuthorization' class using the Composite pattern for modular EST authorization."""
from request.request_context import EstBaseRequestContext

from .base import (
    CertificateProfileAuthorization,
    CompositeAuthorization,
    DomainScopeValidation,
    OnboardingDomainCredentialAuthorization,
    ProtocolAuthorization,
    SecurityConfigAuthorization,
)
from .http import HttpOperationAuthorization


class EstOperationAuthorization(HttpOperationAuthorization):
    """Authorize the requested operation for EstBaseRequestContext."""

    context_type = EstBaseRequestContext
    context_error_message = 'EstOperationAuthorization requires an EstBaseRequestContext.'


class EstAuthorization(CompositeAuthorization):
    """Composite authorization handler for EST requests."""
    def __init__(self, allowed_operations: list[str] | None = None) -> None:
        """Initialize the composite authorization handler with the default set of components.

        Args:
            allowed_operations: List of allowed EST operations. Defaults to ['cr', 'ir'] if not provided.
        """
        super().__init__()

        if allowed_operations is None:
            allowed_operations = ['simpleenroll', 'simplereenroll']

        self.add(DomainScopeValidation())
        self.add(CertificateProfileAuthorization())
        self.add(OnboardingDomainCredentialAuthorization())
        self.add(ProtocolAuthorization(['est']))
        self.add(EstOperationAuthorization(allowed_operations))
        self.add(SecurityConfigAuthorization())
