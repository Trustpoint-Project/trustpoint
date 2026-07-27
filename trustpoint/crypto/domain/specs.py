"""Request/response specs for the redesigned crypto layer."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from crypto.domain.algorithms import EllipticCurveName, HashAlgorithmName, KeyAlgorithm, SignatureAlgorithm


@dataclass(frozen=True, slots=True)
class RsaKeySpec:
    """Specification for an RSA key pair."""

    key_size: int


@dataclass(frozen=True, slots=True)
class EcKeySpec:
    """Specification for an elliptic-curve key pair."""

    curve: EllipticCurveName


class MlDsaVariant(StrEnum):
    """ML-DSA parameter sets."""

    MLDSA44 = 'mldsa44'
    MLDSA65 = 'mldsa65'
    MLDSA87 = 'mldsa87'


@dataclass(frozen=True, slots=True)
class MlDsaKeySpec:
    """Specification for an ML-DSA key pair."""

    variant: MlDsaVariant


type KeySpec = RsaKeySpec | EcKeySpec | MlDsaKeySpec


@dataclass(frozen=True, slots=True)
class SignRequest:
    """A normalized signing request."""

    signature_algorithm: SignatureAlgorithm
    hash_algorithm: HashAlgorithmName
    prehashed: bool = False

    @classmethod
    def rsa_pkcs1v15_sha256(cls) -> SignRequest:
        """Build a common RSA PKCS#1 v1.5 request."""
        return cls(
            signature_algorithm=SignatureAlgorithm.RSA_PKCS1V15,
            hash_algorithm=HashAlgorithmName.SHA256,
        )

    @classmethod
    def mldsa_pure(cls) -> SignRequest:
        """Build a pure ML-DSA request (no hash algorithm needed)."""
        return cls(
            signature_algorithm=SignatureAlgorithm.MLDSA,
            hash_algorithm=HashAlgorithmName.SHA256,  # Placeholder, not used for ML-DSA
        )


def algorithm_for_key_spec(key_spec: KeySpec) -> KeyAlgorithm:
    """Resolve the high-level key algorithm for a key specification."""
    if isinstance(key_spec, RsaKeySpec):
        return KeyAlgorithm.RSA
    if isinstance(key_spec, EcKeySpec):
        return KeyAlgorithm.EC
    return KeyAlgorithm.MLDSA
