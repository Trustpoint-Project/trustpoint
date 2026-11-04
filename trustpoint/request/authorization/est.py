# Copyright (c) 2025 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Provides the 'EstAuthorization' class using the Composite pattern for modular EST authorization."""

from pki.models import IssuedCredentialModel
from request.request_context import BaseRequestContext, EstBaseRequestContext, EstCertificateRequestContext

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

    def authorize(self, context: BaseRequestContext) -> None:
        """Keep renewal bound to the profile of the authenticated certificate."""
        super().authorize(context)
        if isinstance(context, EstCertificateRequestContext) and context.operation == 'simplereenroll':
            certificate = context.client_certificate
            if certificate is None:
                message = 'Reenrollment requires the existing client certificate.'
                context.error(message, http_status=401)
                raise ValueError(message)
            issued = IssuedCredentialModel.get_credential_for_certificate(certificate)
            if context.certificate_profile_model != issued.certificate_profile:
                message = 'Reenrollment must use the existing credential certificate profile.'
                context.error(message, http_status=403)
                raise ValueError(message)
