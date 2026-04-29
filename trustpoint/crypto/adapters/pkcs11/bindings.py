"""Internal PKCS#11 binding types for managed keys."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from crypto.domain.policies import SigningExecutionMode

if TYPE_CHECKING:
    from crypto.domain.algorithms import KeyAlgorithm
    from crypto.domain.refs import ManagedKeyVerificationStatus


@dataclass(frozen=True, slots=True)
class Pkcs11ManagedKeyBinding:
    """Provider-specific PKCS#11 identity for a managed key."""

    key_id: bytes
    algorithm: KeyAlgorithm
    public_key_fingerprint_sha256: str | None = None
    signing_execution_mode: SigningExecutionMode = SigningExecutionMode.COMPLETE_BACKEND
    provider_label: str | None = None

    @property
    def key_id_hex(self) -> str:
        """Return the PKCS#11 object id as a hex string."""
        return self.key_id.hex()


@dataclass(frozen=True, slots=True)
class Pkcs11ManagedKeyVerification:
    """Verification result for a provider-specific PKCS#11 managed-key binding."""

    status: ManagedKeyVerificationStatus
    resolved_public_key_fingerprint_sha256: str | None = None
