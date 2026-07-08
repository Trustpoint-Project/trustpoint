"""Internal binding types for protected imported private keys."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from crypto.domain.policies import SigningExecutionMode

if TYPE_CHECKING:
    from crypto.domain.algorithms import KeyAlgorithm
    from crypto.domain.refs import ManagedKeyVerificationStatus


@dataclass(frozen=True, slots=True)
class ProtectedImportManagedKeyBinding:
    """Encrypted DB binding for an imported private key managed through Trustpoint."""

    key_handle: str
    algorithm: KeyAlgorithm
    encrypted_private_key_pkcs8_der_b64: str
    encryption_metadata: dict[str, object] = field(default_factory=dict)
    public_key_fingerprint_sha256: str | None = None
    signing_execution_mode: SigningExecutionMode = SigningExecutionMode.COMPLETE_BACKEND
    provider_label: str | None = None


@dataclass(frozen=True, slots=True)
class ProtectedImportManagedKeyVerification:
    """Verification result for a protected imported key binding."""

    status: ManagedKeyVerificationStatus
    resolved_public_key_fingerprint_sha256: str | None = None
