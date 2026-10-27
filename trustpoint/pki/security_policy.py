# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Cryptographic policy snapshots, normalized material facts and shared evaluation.

Policy retrieval, certificate-chain validation, issuance permissions and user-facing
context belong to callers. Evaluation here does not query or modify the database.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING, Protocol, cast

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives.asymmetric import ec, mldsa, rsa
from cryptography.x509.oid import SignatureAlgorithmOID
from trustpoint_core.oid import AlgorithmIdentifier, HashAlgorithm, NamedCurve, PublicKeyAlgorithmOid

if TYPE_CHECKING:
    from collections.abc import Mapping

    from cryptography import x509

    from pki.models.certificate import CertificateModel


class CryptographicPolicySource(Protocol):
    """Configuration fields needed to construct a cryptographic policy snapshot."""

    rsa_minimum_key_size: int | None
    not_permitted_ecc_curve_oids: list[str]
    not_permitted_mldsa_variant_oids: list[str]
    not_permitted_signature_algorithm_oids: list[str]


@dataclass(frozen=True)
class CryptographicPolicy:
    """Immutable constraints for one operation, independent of later config changes."""

    rsa_minimum_key_size: int | None = 0
    blocked_curve_oids: frozenset[str] = frozenset()
    blocked_mldsa_oids: frozenset[str] = frozenset()
    blocked_signature_oids: frozenset[str] = frozenset()

    @classmethod
    def from_config(cls, config: CryptographicPolicySource) -> CryptographicPolicy:
        """Copy the active configuration without retaining mutable JSON lists."""
        return cls(
            rsa_minimum_key_size=config.rsa_minimum_key_size,
            blocked_curve_oids=frozenset(config.not_permitted_ecc_curve_oids or []),
            blocked_mldsa_oids=frozenset(config.not_permitted_mldsa_variant_oids or []),
            blocked_signature_oids=frozenset(config.not_permitted_signature_algorithm_oids or []),
        )

    @classmethod
    def from_mapping(cls, policy: Mapping[str, object]) -> CryptographicPolicy:
        """Copy an explicitly requested policy, including deployment restrictions."""
        return cls(
            rsa_minimum_key_size=cast('int | None', policy['rsa_minimum_key_size']),
            blocked_curve_oids=frozenset(cast('list[str]', policy['not_permitted_ecc_curve_oids'])),
            blocked_mldsa_oids=frozenset(cast('list[str]', policy['not_permitted_mldsa_variant_oids'])),
            blocked_signature_oids=frozenset(cast('list[str]', policy['not_permitted_signature_algorithm_oids'])),
        )


@dataclass(frozen=True)
class PublicKeyFacts:
    """Public-key properties shared by crypto objects and persisted certificates."""

    algorithm_oid: str
    key_size: int | None = None
    curve_oid: str | None = None


@dataclass(frozen=True)
class SignatureFacts:
    """Signature identifier and its digest, including parameterized RSA-PSS digests."""

    algorithm_oid: str
    hash_oid: str | None = None
    hash_name: str | None = None


class PolicyViolationCode(StrEnum):
    """Stable identifiers allowing callers to select and present policy violations."""

    RSA_FORBIDDEN = 'rsa_forbidden'
    RSA_KEY_TOO_SMALL = 'rsa_key_too_small'
    ECC_CURVE_UNKNOWN = 'ecc_curve_unknown'
    ECC_CURVE_BLOCKED = 'ecc_curve_blocked'
    MLDSA_VARIANT_BLOCKED = 'mldsa_variant_blocked'
    PUBLIC_KEY_UNKNOWN = 'public_key_unknown'
    SIGNATURE_UNKNOWN = 'signature_unknown'
    SIGNATURE_BLOCKED = 'signature_blocked'
    SIGNATURE_HASH_BLOCKED = 'signature_hash_blocked'


@dataclass(frozen=True)
class PolicyViolation:
    """A policy failure independent of protocol, view, or model exceptions."""

    code: PolicyViolationCode
    message: str


class CryptographicPolicyError(ValueError):
    """A material's normalized properties violate the supplied policy snapshot."""

    def __init__(self, violations: tuple[PolicyViolation, ...]) -> None:
        """Retain structured failures for callers that need more than the first message."""
        self.violations = violations
        super().__init__(' '.join(violation.message for violation in violations))


def curve_oid_for_key(key: ec.EllipticCurvePublicKey) -> str | None:
    """Resolve the named curve using Core's canonical OID registry."""
    try:
        return NamedCurve.from_curve(type(key.curve)).dotted_string
    except ValueError:
        return None


def _normalize_hash_name(name: str) -> str:
    return name.lower().replace('-', '').replace('_', '')


def hash_oid_for_name(name: str) -> str | None:
    """Resolve digest names consistently, including SHA-3 and SHAKE names."""
    normalized = _normalize_hash_name(name)
    return next(
        (
            algorithm.dotted_string
            for algorithm in HashAlgorithm
            if _normalize_hash_name(algorithm.verbose_name) == normalized
        ),
        None,
    )


_MLDSA_PUBLIC_KEY_OIDS = {
    mldsa.MLDSA44PublicKey: PublicKeyAlgorithmOid.ML_DSA_44.dotted_string,
    mldsa.MLDSA65PublicKey: PublicKeyAlgorithmOid.ML_DSA_65.dotted_string,
    mldsa.MLDSA87PublicKey: PublicKeyAlgorithmOid.ML_DSA_87.dotted_string,
}
_MLDSA_OIDS = frozenset(_MLDSA_PUBLIC_KEY_OIDS.values())


def public_key_facts(key: object) -> PublicKeyFacts:
    """Normalize a public key without exposing or loading private key material."""
    if isinstance(key, rsa.RSAPublicKey):
        return PublicKeyFacts(PublicKeyAlgorithmOid.RSA.dotted_string, key_size=key.key_size)
    if isinstance(key, ec.EllipticCurvePublicKey):
        return PublicKeyFacts(PublicKeyAlgorithmOid.ECC.dotted_string, curve_oid=curve_oid_for_key(key))
    for key_type, oid in _MLDSA_PUBLIC_KEY_OIDS.items():
        if isinstance(key, key_type):
            return PublicKeyFacts(oid)
    return PublicKeyFacts(f'unsupported:{type(key).__name__}')


def stored_public_key_facts(certificate: CertificateModel) -> PublicKeyFacts:
    """Normalize indexed certificate metadata without reparsing its PEM."""
    algorithm = certificate.spki_algorithm_oid
    return PublicKeyFacts(
        algorithm,
        key_size=certificate.spki_key_size if algorithm == PublicKeyAlgorithmOid.RSA.dotted_string else None,
        curve_oid=certificate.spki_ec_curve_oid if algorithm == PublicKeyAlgorithmOid.ECC.dotted_string else None,
    )


def signature_facts(signed: x509.Certificate | x509.CertificateSigningRequest) -> SignatureFacts:
    """Read the actual digest, including RSA-PSS parameters; ML-DSA has no digest."""
    try:
        digest = signed.signature_hash_algorithm
    except UnsupportedAlgorithm:
        return SignatureFacts(signed.signature_algorithm_oid.dotted_string)
    return SignatureFacts(
        signed.signature_algorithm_oid.dotted_string,
        hash_oid=hash_oid_for_name(digest.name) if digest is not None else None,
        hash_name=_normalize_hash_name(digest.name) if digest is not None else None,
    )


def stored_signature_facts(certificate: CertificateModel) -> SignatureFacts:
    """Use signature metadata, parsing parameters only for RSA-PSS certificates."""
    oid = certificate.signature_algorithm_oid
    if oid == SignatureAlgorithmOID.RSASSA_PSS.dotted_string:
        try:
            return signature_facts(certificate.get_certificate_serializer().as_crypto())
        except (ValueError, TypeError, UnsupportedAlgorithm):
            return SignatureFacts(oid)
    try:
        digest = AlgorithmIdentifier.from_dotted_string(oid).hash_algorithm
    except ValueError:
        digest = None
    return SignatureFacts(
        oid,
        hash_oid=digest.dotted_string if digest else None,
        hash_name=_normalize_hash_name(digest.verbose_name) if digest else None,
    )


def evaluate_public_key(  # noqa: PLR0911 - One result per independent key policy rule.
    policy: CryptographicPolicy,
    key: PublicKeyFacts,
) -> tuple[PolicyViolation, ...]:
    """Evaluate RSA sentinel/minimum values, ECC curves and ML-DSA variants."""
    code = PolicyViolationCode
    if key.algorithm_oid == PublicKeyAlgorithmOid.RSA.dotted_string:
        minimum = policy.rsa_minimum_key_size
        if minimum is None:
            return (PolicyViolation(code.RSA_FORBIDDEN, 'RSA keys are not permitted by the active security policy.'),)
        if minimum > 0 and (key.key_size is None or key.key_size < minimum):
            return (
                PolicyViolation(
                    code.RSA_KEY_TOO_SMALL,
                    f'RSA key size {key.key_size} bits is below the minimum of {minimum} bits '
                    'required by the active security policy.',
                ),
            )
    elif key.algorithm_oid == PublicKeyAlgorithmOid.ECC.dotted_string:
        if not key.curve_oid:
            return (
                PolicyViolation(
                    code.ECC_CURVE_UNKNOWN,
                    'ECC key has no curve OID. The active security policy cannot be evaluated safely.',
                ),
            )
        if key.curve_oid in policy.blocked_curve_oids:
            return (
                PolicyViolation(
                    code.ECC_CURVE_BLOCKED,
                    f'ECC curve OID {key.curve_oid!r} is not permitted by the active security policy.',
                ),
            )
    elif key.algorithm_oid in _MLDSA_OIDS:
        if key.algorithm_oid in policy.blocked_mldsa_oids:
            return (
                PolicyViolation(
                    code.MLDSA_VARIANT_BLOCKED,
                    f'ML-DSA variant {key.algorithm_oid!r} is not permitted by the active security policy.',
                ),
            )
    else:
        return (
            PolicyViolation(
                code.PUBLIC_KEY_UNKNOWN,
                f'Unknown public key algorithm {key.algorithm_oid!r}. '
                'The active security policy cannot be evaluated safely.',
            ),
        )
    return ()


def evaluate_signature(policy: CryptographicPolicy, signature: SignatureFacts) -> tuple[PolicyViolation, ...]:
    """Compare hash restrictions with hash OIDs and explicit signature restrictions with signature OIDs."""
    if signature.algorithm_oid == SignatureAlgorithmOID.RSASSA_PSS.dotted_string:
        known = signature.hash_oid is not None
    else:
        try:
            algorithm = AlgorithmIdentifier.from_dotted_string(signature.algorithm_oid)
            known = algorithm.public_key_algo_oid is not None and (
                algorithm.hash_algorithm is None or signature.hash_oid is not None
            )
        except ValueError:
            known = False
    if not known:
        return (
            PolicyViolation(
                PolicyViolationCode.SIGNATURE_UNKNOWN,
                f'Certificate uses unknown signature algorithm OID {signature.algorithm_oid!r}. '
                'The active security policy cannot be evaluated safely.',
            ),
        )
    if signature.algorithm_oid in policy.blocked_signature_oids:
        return (
            PolicyViolation(
                PolicyViolationCode.SIGNATURE_BLOCKED,
                f'Signature algorithm OID {signature.algorithm_oid!r} is not permitted by the active security policy.',
            ),
        )
    if signature.hash_oid is not None and signature.hash_oid in policy.blocked_signature_oids:
        return (
            PolicyViolation(
                PolicyViolationCode.SIGNATURE_HASH_BLOCKED,
                f'Signature hash algorithm {signature.hash_name!r} is not permitted by the active security policy.',
            ),
        )
    return ()


def evaluate_cryptographic_policy(
    policy: CryptographicPolicy,
    *,
    key: PublicKeyFacts | None = None,
    signature: SignatureFacts | None = None,
) -> tuple[PolicyViolation, ...]:
    """Evaluate available facts; unsigned builders deliberately have no signature facts."""
    return (evaluate_public_key(policy, key) if key is not None else ()) + (
        evaluate_signature(policy, signature) if signature is not None else ()
    )


def enforce_cryptographic_policy(
    policy: CryptographicPolicy,
    *,
    key: PublicKeyFacts | None = None,
    signature: SignatureFacts | None = None,
) -> None:
    """Raise a ValueError-compatible exception if any shared rule is violated."""
    violations = evaluate_cryptographic_policy(policy, key=key, signature=signature)
    if violations:
        raise CryptographicPolicyError(violations)
