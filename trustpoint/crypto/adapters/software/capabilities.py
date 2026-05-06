"""Capability types for the software backend."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass


def _string_tuple(payload: dict[str, object], key: str) -> tuple[str, ...]:
    """Return a tuple of strings from a serialized capability-list field."""
    value = payload.get(key, [])
    if not isinstance(value, list):
        msg = f'Capability field {key!r} must be a list of strings.'
        raise TypeError(msg)

    if not all(isinstance(item, str) for item in value):
        msg = f'Capability field {key!r} must only contain strings.'
        raise ValueError(msg)

    return tuple(value)


@dataclass(frozen=True, slots=True)
class SoftwareCapabilities:
    """Serializable software backend capability snapshot."""

    supported_key_algorithms: tuple[str, ...]
    supported_signature_algorithms: tuple[str, ...]
    supported_signing_execution_modes: tuple[str, ...]

    def to_json_dict(self) -> dict[str, object]:
        """Serialize the capability snapshot."""
        return {
            'supported_key_algorithms': list(self.supported_key_algorithms),
            'supported_signature_algorithms': list(self.supported_signature_algorithms),
            'supported_signing_execution_modes': list(self.supported_signing_execution_modes),
        }

    @classmethod
    def from_json_dict(cls, payload: dict[str, object]) -> SoftwareCapabilities:
        """Deserialize the capability snapshot."""
        return cls(
            supported_key_algorithms=_string_tuple(payload, 'supported_key_algorithms'),
            supported_signature_algorithms=_string_tuple(payload, 'supported_signature_algorithms'),
            supported_signing_execution_modes=_string_tuple(payload, 'supported_signing_execution_modes'),
        )

    def fingerprint(self) -> str:
        """Return a stable snapshot fingerprint."""
        serialized = json.dumps(self.to_json_dict(), sort_keys=True, separators=(',', ':')).encode('utf-8')
        return hashlib.sha256(serialized).hexdigest()
