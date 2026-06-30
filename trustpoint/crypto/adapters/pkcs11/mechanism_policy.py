"""PKCS#11 sign-operation resolution based on provider capabilities and per-key policy."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import TYPE_CHECKING

from crypto.adapters.pkcs11.mechanisms import (
    ecdsa_mechanism_for_hash,
    rsa_pkcs1v15_mechanism_for_hash,
)
from crypto.domain.algorithms import HashAlgorithmName, KeyAlgorithm, SignatureAlgorithm
from crypto.domain.errors import MechanismUnsupportedError
from crypto.domain.policies import SigningExecutionMode
from pkcs11 import Mechanism

if TYPE_CHECKING:
    from collections.abc import Callable
    from typing import Any

    from crypto.adapters.pkcs11.capability_probe import Pkcs11Capabilities
    from crypto.domain.specs import SignRequest


_RSA_DIGEST_INFO_PREFIX = {
    HashAlgorithmName.SHA224: bytes.fromhex('302d300d06096086480165030402040500041c'),
    HashAlgorithmName.SHA256: bytes.fromhex('3031300d060960864801650304020105000420'),
    HashAlgorithmName.SHA384: bytes.fromhex('3041300d060960864801650304020205000430'),
    HashAlgorithmName.SHA512: bytes.fromhex('3051300d060960864801650304020305000440'),
    HashAlgorithmName.SHA3_224: bytes.fromhex('302b300b0609608648016503040207041c'),
    HashAlgorithmName.SHA3_256: bytes.fromhex('302f300b06096086480165030402080420'),
    HashAlgorithmName.SHA3_384: bytes.fromhex('303f300b06096086480165030402090430'),
    HashAlgorithmName.SHA3_512: bytes.fromhex('304f300b060960864801650304020a0440'),
}

_HASHLIB_HASHES = {
    HashAlgorithmName.SHA224: hashlib.sha224,
    HashAlgorithmName.SHA256: hashlib.sha256,
    HashAlgorithmName.SHA384: hashlib.sha384,
    HashAlgorithmName.SHA512: hashlib.sha512,
    HashAlgorithmName.SHA3_224: hashlib.sha3_224,
    HashAlgorithmName.SHA3_256: hashlib.sha3_256,
    HashAlgorithmName.SHA3_384: hashlib.sha3_384,
    HashAlgorithmName.SHA3_512: hashlib.sha3_512,
}


@dataclass(frozen=True, slots=True)
class Pkcs11SignOperation:
    """Resolved PKCS#11 sign operation."""

    mechanism: Mechanism
    payload: bytes


def resolve_signing_operation(
    *,
    key_algorithm: KeyAlgorithm,
    data: bytes,
    request: SignRequest,
    capabilities: Pkcs11Capabilities,
    signing_execution_mode: SigningExecutionMode,
) -> Pkcs11SignOperation:
    """Resolve a PKCS#11 signing operation from capabilities and key policy.

    There are only two explicit modes:
    - COMPLETE_BACKEND
    - ALLOW_APPLICATION_HASH

    No implicit legacy behavior is applied.
    """
    if key_algorithm is KeyAlgorithm.RSA:
        return _resolve_rsa_signing_operation(
            data=data,
            request=request,
            capabilities=capabilities,
            signing_execution_mode=signing_execution_mode,
        )

    if key_algorithm is KeyAlgorithm.EC:
        return _resolve_ec_signing_operation(
            data=data,
            request=request,
            capabilities=capabilities,
            signing_execution_mode=signing_execution_mode,
        )

    msg = f'Unsupported key algorithm for signing: {key_algorithm!r}'
    raise MechanismUnsupportedError(msg)


def _resolve_rsa_signing_operation(
    *,
    data: bytes,
    request: SignRequest,
    capabilities: Pkcs11Capabilities,
    signing_execution_mode: SigningExecutionMode,
) -> Pkcs11SignOperation:
    """Resolve an RSA sign operation for the selected execution mode."""
    if request.signature_algorithm is not SignatureAlgorithm.RSA_PKCS1V15:
        msg = f'Unsupported RSA signature algorithm: {request.signature_algorithm.value}'
        raise MechanismUnsupportedError(msg)

    raw_mechanism = Mechanism.RSA_PKCS

    if signing_execution_mode is SigningExecutionMode.COMPLETE_BACKEND:
        if request.prehashed:
            msg = 'Complete-backend RSA signing cannot accept prehashed payloads.'
            raise MechanismUnsupportedError(msg)
        exact_mechanism = rsa_pkcs1v15_mechanism_for_hash(request.hash_algorithm)
        if not capabilities.supports(exact_mechanism):
            msg = (
                f'Token does not support the complete in-HSM PKCS#11 mechanism {exact_mechanism.name} '
                f'for {request.signature_algorithm.value} with {request.hash_algorithm.value}.'
            )
            raise MechanismUnsupportedError(msg)

        return Pkcs11SignOperation(mechanism=exact_mechanism, payload=data)

    if signing_execution_mode is SigningExecutionMode.ALLOW_APPLICATION_HASH:
        if capabilities.supports(raw_mechanism):
            digest = _prehashed_or_hash_bytes(data=data, request=request)
            payload = _RSA_DIGEST_INFO_PREFIX[request.hash_algorithm] + digest
            return Pkcs11SignOperation(mechanism=raw_mechanism, payload=payload)

        if request.prehashed:
            msg = (
                f'Token does not support raw PKCS#11 RSA signing ({raw_mechanism.name}); '
                'prehashed RSA payloads cannot be safely signed with complete hash-and-sign mechanisms.'
            )
            raise MechanismUnsupportedError(msg)

        exact_mechanism = rsa_pkcs1v15_mechanism_for_hash(request.hash_algorithm)
        if capabilities.supports(exact_mechanism):
            return Pkcs11SignOperation(mechanism=exact_mechanism, payload=data)

        msg = (
            f'Token does not support either raw PKCS#11 RSA signing ({raw_mechanism.name}) '
            f'or exact in-HSM signing ({exact_mechanism.name}) for '
            f'{request.signature_algorithm.value} with {request.hash_algorithm.value}.'
        )
        raise MechanismUnsupportedError(msg)

    msg = f'Unsupported signing execution mode: {signing_execution_mode!r}'
    raise MechanismUnsupportedError(msg)


def _resolve_ec_signing_operation(
    *,
    data: bytes,
    request: SignRequest,
    capabilities: Pkcs11Capabilities,
    signing_execution_mode: SigningExecutionMode,
) -> Pkcs11SignOperation:
    """Resolve an EC sign operation for the selected execution mode."""
    if request.signature_algorithm is not SignatureAlgorithm.ECDSA:
        msg = f'Unsupported EC signature algorithm: {request.signature_algorithm.value}'
        raise MechanismUnsupportedError(msg)

    raw_mechanism = Mechanism.ECDSA

    if signing_execution_mode is SigningExecutionMode.COMPLETE_BACKEND:
        if request.prehashed:
            msg = 'Complete-backend EC signing cannot accept prehashed payloads.'
            raise MechanismUnsupportedError(msg)
        exact_mechanism = ecdsa_mechanism_for_hash(request.hash_algorithm)
        if not capabilities.supports(exact_mechanism):
            msg = (
                f'Token does not support the complete in-HSM PKCS#11 mechanism {exact_mechanism.name} '
                f'for {request.signature_algorithm.value} with {request.hash_algorithm.value}.'
            )
            raise MechanismUnsupportedError(msg)

        return Pkcs11SignOperation(mechanism=exact_mechanism, payload=data)

    if signing_execution_mode is SigningExecutionMode.ALLOW_APPLICATION_HASH:
        if capabilities.supports(raw_mechanism):
            digest = _prehashed_or_hash_bytes(data=data, request=request)
            return Pkcs11SignOperation(mechanism=raw_mechanism, payload=digest)

        if request.prehashed:
            msg = (
                f'Token does not support raw PKCS#11 EC signing ({raw_mechanism.name}); '
                'prehashed EC payloads cannot be safely signed with complete hash-and-sign mechanisms.'
            )
            raise MechanismUnsupportedError(msg)

        exact_mechanism = ecdsa_mechanism_for_hash(request.hash_algorithm)
        if capabilities.supports(exact_mechanism):
            return Pkcs11SignOperation(mechanism=exact_mechanism, payload=data)

        msg = (
            f'Token does not support either raw PKCS#11 EC signing ({raw_mechanism.name}) '
            f'or exact in-HSM signing ({exact_mechanism.name}) for '
            f'{request.signature_algorithm.value} with {request.hash_algorithm.value}.'
        )
        raise MechanismUnsupportedError(msg)

    msg = f'Unsupported signing execution mode: {signing_execution_mode!r}'
    raise MechanismUnsupportedError(msg)


def _hash_bytes(*, data: bytes, algorithm: HashAlgorithmName) -> bytes:
    """Hash bytes for ALLOW_APPLICATION_HASH mode."""
    return bytes(_hash_factory(algorithm)(data).digest())


def _prehashed_or_hash_bytes(*, data: bytes, request: SignRequest) -> bytes:
    """Return an already-computed digest or hash the payload for raw mechanisms."""
    if not request.prehashed:
        return _hash_bytes(data=data, algorithm=request.hash_algorithm)

    expected_size = _digest_size(request.hash_algorithm)
    if len(data) != expected_size:
        msg = (
            f'Prehashed payload length {len(data)} does not match '
            f'{request.hash_algorithm.value} digest length {expected_size}.'
        )
        raise MechanismUnsupportedError(msg)
    return data


def _digest_size(algorithm: HashAlgorithmName) -> int:
    """Return the digest size for a supported hash algorithm."""
    return int(_hash_factory(algorithm)().digest_size)


def _hash_factory(algorithm: HashAlgorithmName) -> Callable[..., Any]:
    """Return the hashlib constructor for a supported hash algorithm."""
    try:
        return _HASHLIB_HASHES[algorithm]
    except KeyError as exc:
        msg = f'Unsupported hash algorithm: {algorithm!r}'
        raise MechanismUnsupportedError(msg) from exc
