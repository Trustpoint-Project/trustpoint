"""REST backend scaffold."""

from __future__ import annotations

from typing import TYPE_CHECKING, Never

from crypto.domain.errors import ProviderOperationNotImplementedError

if TYPE_CHECKING:
    from crypto.adapters.rest.bindings import RestManagedKeyBinding
    from crypto.adapters.rest.capabilities import RestCapabilities
    from crypto.adapters.rest.config import RestProviderProfile
    from crypto.domain.algorithms import SupportedPublicKey
    from crypto.domain.policies import KeyPolicy
    from crypto.domain.specs import KeySpec, SignRequest


class RestBackend:
    """Scaffold for a remote REST-based crypto backend."""

    provider_name = 'rest'

    def __init__(self, *, profile: RestProviderProfile) -> None:
        """Initialize the REST backend scaffold."""
        self._profile = profile
        self._capabilities: RestCapabilities | None = None

    def verify_provider(self) -> None:
        """Reject the scaffold until a real REST provider implementation exists."""
        self.probe_capabilities()

    def refresh_capabilities(self) -> RestCapabilities:
        """Refresh the cached capability snapshot."""
        self._capabilities = None
        return self.probe_capabilities()

    def current_capabilities(self) -> RestCapabilities | None:
        """Return the current cached capability snapshot."""
        return self._capabilities

    def close(self) -> None:
        """Release runtime state."""
        self._capabilities = None

    def probe_capabilities(self) -> RestCapabilities:
        """Reject the scaffold until a real REST provider implementation exists."""
        self._profile.require_auth_value()
        msg = 'REST backend support is scaffolded only and cannot be configured for a Trustpoint instance yet.'
        raise ProviderOperationNotImplementedError(
            msg,
        )

    def generate_managed_key(self, *, alias: str, key_spec: KeySpec, policy: KeyPolicy) -> RestManagedKeyBinding:
        """Create a managed key on the remote backend."""
        msg = 'REST backend scaffold does not implement generate_managed_key yet.'
        raise ProviderOperationNotImplementedError(
            msg,
        )

    def verify_managed_key(self, key: RestManagedKeyBinding) -> Never:
        """Verify a remote managed key binding."""
        msg = 'REST backend scaffold does not implement verify_managed_key yet.'
        raise ProviderOperationNotImplementedError(
            msg,
        )

    def get_public_key(self, key: RestManagedKeyBinding) -> SupportedPublicKey:
        """Load the public key for a remote managed key."""
        msg = 'REST backend scaffold does not implement get_public_key yet.'
        raise ProviderOperationNotImplementedError(
            msg,
        )

    def sign(self, *, key: RestManagedKeyBinding, data: bytes, request: SignRequest) -> bytes:
        """Sign bytes using a remote managed key."""
        msg = 'REST backend scaffold does not implement sign yet.'
        raise ProviderOperationNotImplementedError(
            msg,
        )

    def destroy_managed_key(self, key: RestManagedKeyBinding) -> None:
        """Best-effort removal of an orphaned remote managed key."""
        msg = 'REST backend scaffold does not implement destroy_managed_key yet.'
        raise ProviderOperationNotImplementedError(
            msg,
        )
