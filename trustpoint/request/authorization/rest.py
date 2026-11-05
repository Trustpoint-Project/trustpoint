# Copyright (c) 2025 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Provides the 'RestAuthorization' class using the Composite pattern for modular REST authorization."""

from request.request_context import RestBaseRequestContext

from .base import (
    CertificateProfileAuthorization,
    CompositeAuthorization,
    DomainScopeValidation,
    OnboardingDomainCredentialAuthorization,
    ProtocolAuthorization,
    SecurityConfigAuthorization,
)
from .http import HttpOperationAuthorization


class RestOperationAuthorization(HttpOperationAuthorization):
    """Authorize the requested operation for RestBaseRequestContext."""

    context_type = RestBaseRequestContext
    context_error_message = 'RestOperationAuthorization requires a RestBaseRequestContext.'


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
