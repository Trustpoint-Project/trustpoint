# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Capability types for the REST backend."""

from __future__ import annotations

from dataclasses import dataclass

from crypto.domain.capabilities import capability_fingerprint
from crypto.domain.capabilities import string_tuple as _string_tuple


@dataclass(frozen=True, slots=True)
class RestCapabilities:
    """Serializable REST backend capability snapshot."""

    supported_key_algorithms: tuple[str, ...]
    supported_signature_algorithms: tuple[str, ...]
    supported_signing_execution_modes: tuple[str, ...]
    implemented_operations: tuple[str, ...]

    def to_json_dict(self) -> dict[str, object]:
        """Serialize the capability snapshot."""
        return {
            'supported_key_algorithms': list(self.supported_key_algorithms),
            'supported_signature_algorithms': list(self.supported_signature_algorithms),
            'supported_signing_execution_modes': list(self.supported_signing_execution_modes),
            'implemented_operations': list(self.implemented_operations),
        }

    @classmethod
    def from_json_dict(cls, payload: dict[str, object]) -> RestCapabilities:
        """Deserialize the capability snapshot."""
        return cls(
            supported_key_algorithms=_string_tuple(payload, 'supported_key_algorithms'),
            supported_signature_algorithms=_string_tuple(payload, 'supported_signature_algorithms'),
            supported_signing_execution_modes=_string_tuple(payload, 'supported_signing_execution_modes'),
            implemented_operations=_string_tuple(payload, 'implemented_operations'),
        )

    def fingerprint(self) -> str:
        """Return a stable snapshot fingerprint."""
        return capability_fingerprint(self.to_json_dict())
