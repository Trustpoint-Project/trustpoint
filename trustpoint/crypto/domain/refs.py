"""Stable references to backend-managed crypto material."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING

from crypto.domain.policies import SigningExecutionMode

if TYPE_CHECKING:
    from crypto.domain.algorithms import KeyAlgorithm


@dataclass(frozen=True, slots=True)
class ManagedKeyRef:
    """Opaque application-facing reference to a managed key."""

    alias: str
    provider: str
    key_id: bytes
    label: str
    algorithm: KeyAlgorithm
    public_key_fingerprint_sha256: str | None = None
    signing_execution_mode: SigningExecutionMode = SigningExecutionMode.COMPLETE_HSM

    @property
    def key_id_hex(self) -> str:
        """Return the PKCS#11 object id as a hex string."""
        return self.key_id.hex()


class ManagedKeyVerificationStatus(str, Enum):
    """Verification outcome for a managed-key reference."""

    PRESENT = 'present'
    MISSING = 'missing'
    MISMATCH = 'mismatch'


@dataclass(frozen=True, slots=True)
class ManagedKeyVerification:
    """Result of verifying that a managed-key reference still resolves correctly."""

    key: ManagedKeyRef
    status: ManagedKeyVerificationStatus
    resolved_public_key_fingerprint_sha256: str | None = None

    @property
    def is_present(self) -> bool:
        """Whether the managed key resolves and matches expectations."""
        return self.status is ManagedKeyVerificationStatus.PRESENT
