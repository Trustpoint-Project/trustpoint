"""Internal backend-adapter protocols used by the application service."""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from crypto.domain.algorithms import SupportedPublicKey
    from crypto.domain.policies import KeyPolicy
    from crypto.domain.refs import ManagedKeyVerificationStatus
    from crypto.domain.specs import KeySpec, SignRequest


class BackendManagedKeyVerification(Protocol):
    """Minimal verification result shape expected from backend adapters."""

    status: ManagedKeyVerificationStatus
    resolved_public_key_fingerprint_sha256: str | None


class ManagedKeyBackendAdapter(Protocol):
    """Internal protocol for backend-kind-specific managed-key adapters."""

    provider_name: str

    def verify_provider(self) -> None:
        """Validate that the configured provider can be loaded and used."""

    def generate_managed_key(self, *, alias: str, key_spec: KeySpec, policy: KeyPolicy) -> object:
        """Generate a backend-managed key binding."""

    def verify_managed_key(self, key: object) -> BackendManagedKeyVerification:
        """Verify that a backend-managed key binding still resolves correctly."""

    def get_public_key(self, key: object) -> SupportedPublicKey:
        """Load the public key for a backend-managed key binding."""

    def sign(self, *, key: object, data: bytes, request: SignRequest) -> bytes:
        """Sign bytes with a backend-managed key binding."""

    def destroy_managed_key(self, key: object) -> None:
        """Best-effort cleanup of a generated binding after persistence failure."""

    def close(self) -> None:
        """Release runtime resources held by the adapter."""
