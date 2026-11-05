# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Capability types for the software backend."""

from __future__ import annotations

from dataclasses import dataclass

from crypto.domain.algorithms import KeyAlgorithm
from crypto.domain.capabilities import capability_fingerprint
from crypto.domain.capabilities import string_tuple as _string_tuple
from crypto.domain.policies import SigningExecutionMode


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
        return capability_fingerprint(self.to_json_dict())


SOFTWARE_CAPABILITIES = SoftwareCapabilities(
    supported_key_algorithms=(KeyAlgorithm.RSA.value, KeyAlgorithm.EC.value, KeyAlgorithm.MLDSA.value),
    supported_signature_algorithms=('rsa_pkcs1v15', 'ecdsa', 'mldsa'),
    supported_signing_execution_modes=(
        SigningExecutionMode.COMPLETE_BACKEND.value,
        SigningExecutionMode.ALLOW_APPLICATION_HASH.value,
    ),
)
