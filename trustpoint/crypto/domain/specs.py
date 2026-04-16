"""Request/response specs for the redesigned crypto layer."""

from __future__ import annotations

from dataclasses import dataclass

from crypto.domain.algorithms import EllipticCurveName, HashAlgorithmName, KeyAlgorithm, SignatureAlgorithm


@dataclass(frozen=True, slots=True)
class RsaKeySpec:
    """Specification for an RSA key pair."""

    key_size: int
    public_exponent: int = 65537


@dataclass(frozen=True, slots=True)
class EcKeySpec:
    """Specification for an elliptic-curve key pair."""

    curve: EllipticCurveName


type KeySpec = RsaKeySpec | EcKeySpec


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
    def ecdsa_sha256(cls) -> SignRequest:
        """Build a common ECDSA request."""
        return cls(
            signature_algorithm=SignatureAlgorithm.ECDSA,
            hash_algorithm=HashAlgorithmName.SHA256,
        )


def algorithm_for_key_spec(key_spec: KeySpec) -> KeyAlgorithm:
    """Resolve the high-level key algorithm for a key specification."""
    if isinstance(key_spec, RsaKeySpec):
        return KeyAlgorithm.RSA
    return KeyAlgorithm.EC
