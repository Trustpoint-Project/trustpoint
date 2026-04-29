"""Internal binding types for the REST backend."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from crypto.domain.policies import SigningExecutionMode

if TYPE_CHECKING:
    from crypto.domain.algorithms import KeyAlgorithm
    from crypto.domain.refs import ManagedKeyVerificationStatus


@dataclass(frozen=True, slots=True)
class RestManagedKeyBinding:
    """Remote managed-key binding."""

    remote_key_id: str
    algorithm: KeyAlgorithm
    remote_key_version: str | None = None
    public_key_fingerprint_sha256: str | None = None
    signing_execution_mode: SigningExecutionMode = SigningExecutionMode.COMPLETE_BACKEND
    provider_label: str | None = None


@dataclass(frozen=True, slots=True)
class RestManagedKeyVerification:
    """Verification result for a REST-managed key binding."""

    status: ManagedKeyVerificationStatus
    resolved_public_key_fingerprint_sha256: str | None = None
