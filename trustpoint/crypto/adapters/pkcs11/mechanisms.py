"""PKCS#11 mechanism and template selection."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import TYPE_CHECKING

from crypto.domain.algorithms import EllipticCurveName, HashAlgorithmName, KeyAlgorithm, SignatureAlgorithm
from crypto.domain.errors import MechanismUnsupportedError
from crypto.domain.policies import KeyPolicy, KeyUsage
from pkcs11 import Attribute, KeyType, Mechanism
from pkcs11.util.ec import encode_named_curve_parameters

if TYPE_CHECKING:
    from crypto.adapters.pkcs11.capability_probe import Pkcs11Capabilities
    from crypto.domain.specs import SignRequest

_RSA_PKCS1_V15_MECHANISMS = {
    HashAlgorithmName.SHA224: Mechanism.SHA224_RSA_PKCS,
    HashAlgorithmName.SHA256: Mechanism.SHA256_RSA_PKCS,
    HashAlgorithmName.SHA384: Mechanism.SHA384_RSA_PKCS,
    HashAlgorithmName.SHA512: Mechanism.SHA512_RSA_PKCS,
}

_ECDSA_MECHANISMS = {
    HashAlgorithmName.SHA224: Mechanism.ECDSA_SHA224,
    HashAlgorithmName.SHA256: Mechanism.ECDSA_SHA256,
    HashAlgorithmName.SHA384: Mechanism.ECDSA_SHA384,
    HashAlgorithmName.SHA512: Mechanism.ECDSA_SHA512,
}

_RSA_DIGEST_INFO_PREFIX = {
    HashAlgorithmName.SHA224: bytes.fromhex('302d300d06096086480165030402040500041c'),
    HashAlgorithmName.SHA256: bytes.fromhex('3031300d060960864801650304020105000420'),
    HashAlgorithmName.SHA384: bytes.fromhex('3041300d060960864801650304020205000430'),
    HashAlgorithmName.SHA512: bytes.fromhex('3051300d060960864801650304020305000440'),
}

_CURVE_OIDS = {
    EllipticCurveName.SECP256R1: '1.2.840.10045.3.1.7',
    EllipticCurveName.SECP384R1: '1.3.132.0.34',
    EllipticCurveName.SECP521R1: '1.3.132.0.35',
}


@dataclass(frozen=True, slots=True)
class Pkcs11SignOperation:
    """Resolved PKCS#11 sign operation."""

    mechanism: Mechanism
    payload: bytes


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
    return encode_named_curve_parameters(_CURVE_OIDS[curve])


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


def signing_operation_for_request(
    *,
    key_algorithm: KeyAlgorithm,
    data: bytes,
    request: SignRequest,
    capabilities: Pkcs11Capabilities | None = None,
) -> Pkcs11SignOperation:
    """Resolve the PKCS#11 mechanism and payload for a signing request.

    Portability rule:
    - Prefer raw sign mechanisms when available.
    - Fall back to combined hash+sign mechanisms only when needed.
    """
    if key_algorithm is KeyAlgorithm.RSA:
        return _rsa_signing_operation(data=data, request=request, capabilities=capabilities)

    if key_algorithm is KeyAlgorithm.EC:
        return _ec_signing_operation(data=data, request=request, capabilities=capabilities)

    msg = f'Unsupported key algorithm: {key_algorithm!r}'
    raise MechanismUnsupportedError(msg)


def _rsa_signing_operation(
    *,
    data: bytes,
    request: SignRequest,
    capabilities: Pkcs11Capabilities | None,
) -> Pkcs11SignOperation:
    if request.signature_algorithm is not SignatureAlgorithm.RSA_PKCS1V15:
        msg = f'Unsupported RSA signature algorithm: {request.signature_algorithm.value}'
        raise MechanismUnsupportedError(msg)

    raw_mechanism = Mechanism.RSA_PKCS
    combined_mechanism = _RSA_PKCS1_V15_MECHANISMS[request.hash_algorithm]

    if capabilities is None:
        if request.prehashed:
            return Pkcs11SignOperation(
                mechanism=raw_mechanism,
                payload=_RSA_DIGEST_INFO_PREFIX[request.hash_algorithm] + data,
            )
        return Pkcs11SignOperation(
            mechanism=combined_mechanism,
            payload=data,
        )

    digest = data if request.prehashed else _hash_bytes(data=data, algorithm=request.hash_algorithm)
    raw_payload = _RSA_DIGEST_INFO_PREFIX[request.hash_algorithm] + digest

    if capabilities.supports(raw_mechanism):
        return Pkcs11SignOperation(
            mechanism=raw_mechanism,
            payload=raw_payload,
        )

    if not request.prehashed and capabilities.supports(combined_mechanism):
        return Pkcs11SignOperation(
            mechanism=combined_mechanism,
            payload=data,
        )

    msg = (
        f'No supported PKCS#11 RSA signing mechanism is available for '
        f'{request.signature_algorithm.value} with {request.hash_algorithm.value}.'
    )
    raise MechanismUnsupportedError(msg)


def _ec_signing_operation(
    *,
    data: bytes,
    request: SignRequest,
    capabilities: Pkcs11Capabilities | None,
) -> Pkcs11SignOperation:
    if request.signature_algorithm is not SignatureAlgorithm.ECDSA:
        msg = f'Unsupported EC signature algorithm: {request.signature_algorithm.value}'
        raise MechanismUnsupportedError(msg)

    raw_mechanism = Mechanism.ECDSA
    combined_mechanism = _ECDSA_MECHANISMS[request.hash_algorithm]

    if capabilities is None:
        if request.prehashed:
            return Pkcs11SignOperation(mechanism=raw_mechanism, payload=data)
        return Pkcs11SignOperation(
            mechanism=combined_mechanism,
            payload=data,
        )

    digest = data if request.prehashed else _hash_bytes(data=data, algorithm=request.hash_algorithm)

    if capabilities.supports(raw_mechanism):
        return Pkcs11SignOperation(
            mechanism=raw_mechanism,
            payload=digest,
        )

    if not request.prehashed and capabilities.supports(combined_mechanism):
        return Pkcs11SignOperation(
            mechanism=combined_mechanism,
            payload=data,
        )

    msg = (
        f'No supported PKCS#11 EC signing mechanism is available for '
        f'{request.signature_algorithm.value} with {request.hash_algorithm.value}.'
    )
    raise MechanismUnsupportedError(msg)


def _hash_bytes(*, data: bytes, algorithm: HashAlgorithmName) -> bytes:
    if algorithm is HashAlgorithmName.SHA224:
        return hashlib.sha224(data).digest()
    if algorithm is HashAlgorithmName.SHA256:
        return hashlib.sha256(data).digest()
    if algorithm is HashAlgorithmName.SHA384:
        return hashlib.sha384(data).digest()
    if algorithm is HashAlgorithmName.SHA512:
        return hashlib.sha512(data).digest()
    msg = f'Unsupported hash algorithm: {algorithm!r}'
    raise MechanismUnsupportedError(msg)
