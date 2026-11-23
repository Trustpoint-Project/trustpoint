# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Provides the 'ScepAuthorization' class using the Composite pattern for modular SCEP authorization."""

from .base import (
    CertificateProfileAuthorization,
    CompositeAuthorization,
    DomainScopeValidation,
    OnboardingDomainCredentialAuthorization,
    ProtocolAuthorization,
    SecurityConfigAuthorization,
)


class ScepAuthorization(CompositeAuthorization):
    """Composite authorization handler for SCEP requests."""

    def __init__(self) -> None:
        """Initialize the default component set for PKCSReq and RenewalReq."""
        super().__init__()
        self.add(DomainScopeValidation())
        self.add(CertificateProfileAuthorization())
        self.add(OnboardingDomainCredentialAuthorization())
        self.add(ProtocolAuthorization(['scep']))
        self.add(SecurityConfigAuthorization())
