"""Stable application-facing references to backend-managed crypto material."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from uuid import UUID

    from crypto.domain.algorithms import KeyAlgorithm
    from crypto.domain.policies import SigningExecutionMode


@dataclass(frozen=True, slots=True)
class ManagedKeyRef:
    """Opaque application-facing reference to a managed key.

    This handle is intentionally provider-agnostic. PKCS#11 object identity is
    persisted server-side and must not leak into business code.
    """

    id: UUID
    alias: str
    algorithm: KeyAlgorithm
    public_key_fingerprint_sha256: str
    signing_execution_mode: SigningExecutionMode


class ManagedKeyVerificationStatus(StrEnum):
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
