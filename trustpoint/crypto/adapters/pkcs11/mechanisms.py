"""PKCS#11 mechanism and template selection helpers."""

from __future__ import annotations

from typing import cast

from crypto.domain.algorithms import EllipticCurveName, HashAlgorithmName, KeyAlgorithm
from crypto.domain.errors import MechanismUnsupportedError
from crypto.domain.policies import KeyPolicy, KeyUsage
from pkcs11 import Attribute, KeyType, Mechanism  # type: ignore[import-untyped]
from pkcs11.util.ec import encode_named_curve_parameters  # type: ignore[import-untyped]


def _build_hash_mechanism_map(member_names: dict[HashAlgorithmName, str]) -> dict[HashAlgorithmName, Mechanism]:
    """Build a hash-to-mechanism map from Mechanism member names."""
    mapping: dict[HashAlgorithmName, Mechanism] = {}
    for hash_algorithm, member_name in member_names.items():
        mechanism = getattr(Mechanism, member_name, None)
        if mechanism is not None:
            mapping[hash_algorithm] = mechanism
    return mapping


_RSA_PKCS1_V15_MECHANISMS = _build_hash_mechanism_map(
    {
        HashAlgorithmName.SHA224: 'SHA224_RSA_PKCS',
        HashAlgorithmName.SHA256: 'SHA256_RSA_PKCS',
        HashAlgorithmName.SHA384: 'SHA384_RSA_PKCS',
        HashAlgorithmName.SHA512: 'SHA512_RSA_PKCS',
    }
)

_ECDSA_MECHANISMS = _build_hash_mechanism_map(
    {
        HashAlgorithmName.SHA224: 'ECDSA_SHA224',
        HashAlgorithmName.SHA256: 'ECDSA_SHA256',
        HashAlgorithmName.SHA384: 'ECDSA_SHA384',
        HashAlgorithmName.SHA512: 'ECDSA_SHA512',
    }
)

_CURVE_OIDS = {
    EllipticCurveName.SECP256R1: '1.2.840.10045.3.1.7',
    EllipticCurveName.SECP384R1: '1.3.132.0.34',
    EllipticCurveName.SECP521R1: '1.3.132.0.35',
}


def key_type_for_algorithm(algorithm: KeyAlgorithm) -> KeyType:
    """Map a domain key algorithm to a PKCS#11 key type."""
    if algorithm is KeyAlgorithm.RSA:
        return KeyType.RSA
    if algorithm is KeyAlgorithm.EC:
        return KeyType.EC
    msg = f'Unsupported key algorithm: {algorithm!r}'
    raise MechanismUnsupportedError(msg)


def ec_parameters_for_curve(curve: EllipticCurveName) -> bytes:
    """Return DER-encoded EC domain parameters for a named curve."""
    return cast('bytes', encode_named_curve_parameters(_CURVE_OIDS[curve]))


def private_key_template(*, key_id: bytes, label: str, policy: KeyPolicy) -> dict[Attribute, object]:
    """Build the private-key template for a generated key pair."""
    template: dict[Attribute, object] = {
        Attribute.ID: key_id,
        Attribute.LABEL: label,
        Attribute.TOKEN: not policy.ephemeral,
        Attribute.PRIVATE: True,
        Attribute.SENSITIVE: True,
        Attribute.EXTRACTABLE: policy.extractable,
    }

    if policy.can_sign:
        template[Attribute.SIGN] = True
    if KeyUsage.DECRYPT in policy.usages:
        template[Attribute.DECRYPT] = True
    if KeyUsage.UNWRAP in policy.usages:
        template[Attribute.UNWRAP] = True
    return template


def public_key_template(*, key_id: bytes, label: str, policy: KeyPolicy) -> dict[Attribute, object]:
    """Build the public-key template for a generated key pair."""
    template: dict[Attribute, object] = {
        Attribute.ID: key_id,
        Attribute.LABEL: label,
        Attribute.TOKEN: not policy.ephemeral,
        Attribute.PRIVATE: False,
    }

    if policy.can_sign:
        template[Attribute.VERIFY] = True
    if KeyUsage.ENCRYPT in policy.usages:
        template[Attribute.ENCRYPT] = True
    if KeyUsage.WRAP in policy.usages:
        template[Attribute.WRAP] = True
    return template


def rsa_pkcs1v15_hash_mechanisms() -> dict[HashAlgorithmName, Mechanism]:
    """Return supported exact RSA PKCS#1 v1.5 hash+sign mechanisms."""
    return dict(_RSA_PKCS1_V15_MECHANISMS)


def ecdsa_hash_mechanisms() -> dict[HashAlgorithmName, Mechanism]:
    """Return supported exact ECDSA hash+sign mechanisms."""
    return dict(_ECDSA_MECHANISMS)


def rsa_pkcs1v15_mechanism_for_hash(hash_algorithm: HashAlgorithmName) -> Mechanism:
    """Return the exact PKCS#11 RSA PKCS#1 v1.5 mechanism for a hash."""
    mechanism = _RSA_PKCS1_V15_MECHANISMS.get(hash_algorithm)
    if mechanism is None:
        msg = f'No PKCS#11 RSA PKCS#1 v1.5 mechanism mapping is defined for hash {hash_algorithm.value!r}.'
        raise MechanismUnsupportedError(msg)
    return mechanism


def ecdsa_mechanism_for_hash(hash_algorithm: HashAlgorithmName) -> Mechanism:
    """Return the exact PKCS#11 ECDSA hash+sign mechanism for a hash."""
    mechanism = _ECDSA_MECHANISMS.get(hash_algorithm)
    if mechanism is None:
        msg = f'No PKCS#11 ECDSA mechanism mapping is defined for hash {hash_algorithm.value!r}.'
        raise MechanismUnsupportedError(msg)
    return mechanism
