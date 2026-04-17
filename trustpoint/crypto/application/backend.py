"""Application-facing crypto backend contract."""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from crypto.domain.algorithms import SupportedPublicKey
    from crypto.domain.policies import KeyPolicy
    from crypto.domain.refs import ManagedKeyRef, ManagedKeyVerification
    from crypto.domain.specs import KeySpec, SignRequest


class CryptoBackend(Protocol):
    """Minimal application-facing backend contract for managed key operations."""

    provider_name: str

    def verify_provider(self) -> None:
        """Validate that the configured provider can be loaded and used."""

    def generate_managed_key(self, *, alias: str, key_spec: KeySpec, policy: KeyPolicy) -> ManagedKeyRef:
        """Generate and persist a new backend-managed key."""

    def verify_managed_key(self, key: ManagedKeyRef) -> ManagedKeyVerification:
        """Verify that a managed-key reference still resolves to the expected key."""

    def get_public_key(self, key: ManagedKeyRef) -> SupportedPublicKey:
        """Load the public key for a managed key reference."""

    def sign(self, *, key: ManagedKeyRef, data: bytes, request: SignRequest) -> bytes:
        """Sign bytes with a managed key."""
