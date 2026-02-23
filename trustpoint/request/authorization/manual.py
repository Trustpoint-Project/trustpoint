"""Provides the 'ManualAuthorization' class using the Composite pattern for modular manual authorization."""

from .base import (
    CertificateProfileAuthorization,
    CompositeAuthorization,
    DomainScopeValidation,
    ProtocolAuthorization,
)


class ManualAuthorization(CompositeAuthorization):
    """Composite authorization handler for manual requests."""
    def __init__(self) -> None:
        """Initialize the composite authorization handler with the default set of components."""
        super().__init__()

        self.add(DomainScopeValidation())
        self.add(CertificateProfileAuthorization())
        self.add(ProtocolAuthorization(['manual']))
