"""REST backend scaffold."""

from __future__ import annotations

from typing import TYPE_CHECKING

from crypto.adapters.rest.capabilities import RestCapabilities
from crypto.domain.errors import ProviderOperationNotImplementedError
from crypto.domain.policies import SigningExecutionMode

if TYPE_CHECKING:
    from crypto.adapters.rest.bindings import RestManagedKeyBinding
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
        """Validate local REST backend configuration."""
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
        """Return the current scaffold capability snapshot."""
        self._profile.require_auth_value()
        if self._capabilities is None:
            self._capabilities = RestCapabilities(
                supported_key_algorithms=(),
                supported_signature_algorithms=(),
                supported_signing_execution_modes=(
                    SigningExecutionMode.COMPLETE_BACKEND.value,
                    SigningExecutionMode.ALLOW_APPLICATION_HASH.value,
                ),
                implemented_operations=(),
            )
        return self._capabilities

    def generate_managed_key(self, *, alias: str, key_spec: KeySpec, policy: KeyPolicy) -> RestManagedKeyBinding:
        """Create a managed key on the remote backend."""
        raise ProviderOperationNotImplementedError(
            'REST backend scaffold does not implement generate_managed_key yet.',
        )

    def verify_managed_key(self, key: RestManagedKeyBinding):
        """Verify a remote managed key binding."""
        raise ProviderOperationNotImplementedError(
            'REST backend scaffold does not implement verify_managed_key yet.',
        )

    def get_public_key(self, key: RestManagedKeyBinding) -> SupportedPublicKey:
        """Load the public key for a remote managed key."""
        raise ProviderOperationNotImplementedError(
            'REST backend scaffold does not implement get_public_key yet.',
        )

    def sign(self, *, key: RestManagedKeyBinding, data: bytes, request: SignRequest) -> bytes:
        """Sign bytes using a remote managed key."""
        raise ProviderOperationNotImplementedError(
            'REST backend scaffold does not implement sign yet.',
        )

    def destroy_managed_key(self, key: RestManagedKeyBinding) -> None:
        """Best-effort removal of an orphaned remote managed key."""
        raise ProviderOperationNotImplementedError(
            'REST backend scaffold does not implement destroy_managed_key yet.',
        )
