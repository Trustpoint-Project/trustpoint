"""Stable references to backend-managed crypto material."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

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

    @property
    def key_id_hex(self) -> str:
        """Return the PKCS#11 object id as a hex string."""
        return self.key_id.hex()
