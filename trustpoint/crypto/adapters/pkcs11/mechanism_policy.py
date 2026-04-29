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
from pkcs11 import Mechanism  # type: ignore[import-untyped]

if TYPE_CHECKING:
    from crypto.adapters.pkcs11.capability_probe import Pkcs11Capabilities
    from crypto.domain.specs import SignRequest


_RSA_DIGEST_INFO_PREFIX = {
    HashAlgorithmName.SHA224: bytes.fromhex('302d300d06096086480165030402040500041c'),
    HashAlgorithmName.SHA256: bytes.fromhex('3031300d060960864801650304020105000420'),
    HashAlgorithmName.SHA384: bytes.fromhex('3041300d060960864801650304020205000430'),
    HashAlgorithmName.SHA512: bytes.fromhex('3051300d060960864801650304020305000440'),
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
    if request.prehashed:
        msg = (
            'Managed PKCS#11 signing does not accept prehashed payloads. '
            'Trustpoint requires the backend to control hashing/sign preparation.'
        )
        raise MechanismUnsupportedError(msg)

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

    exact_mechanism = rsa_pkcs1v15_mechanism_for_hash(request.hash_algorithm)
    raw_mechanism = Mechanism.RSA_PKCS

    if signing_execution_mode is SigningExecutionMode.COMPLETE_BACKEND:
        if not capabilities.supports(exact_mechanism):
            msg = (
                f'Token does not support the complete in-HSM PKCS#11 mechanism {exact_mechanism.name} '
                f'for {request.signature_algorithm.value} with {request.hash_algorithm.value}.'
            )
            raise MechanismUnsupportedError(msg)

        return Pkcs11SignOperation(mechanism=exact_mechanism, payload=data)

    if signing_execution_mode is SigningExecutionMode.ALLOW_APPLICATION_HASH:
        if capabilities.supports(raw_mechanism):
            digest = _hash_bytes(data=data, algorithm=request.hash_algorithm)
            payload = _RSA_DIGEST_INFO_PREFIX[request.hash_algorithm] + digest
            return Pkcs11SignOperation(mechanism=raw_mechanism, payload=payload)

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

    exact_mechanism = ecdsa_mechanism_for_hash(request.hash_algorithm)
    raw_mechanism = Mechanism.ECDSA

    if signing_execution_mode is SigningExecutionMode.COMPLETE_BACKEND:
        if not capabilities.supports(exact_mechanism):
            msg = (
                f'Token does not support the complete in-HSM PKCS#11 mechanism {exact_mechanism.name} '
                f'for {request.signature_algorithm.value} with {request.hash_algorithm.value}.'
            )
            raise MechanismUnsupportedError(msg)

        return Pkcs11SignOperation(mechanism=exact_mechanism, payload=data)

    if signing_execution_mode is SigningExecutionMode.ALLOW_APPLICATION_HASH:
        if capabilities.supports(raw_mechanism):
            digest = _hash_bytes(data=data, algorithm=request.hash_algorithm)
            return Pkcs11SignOperation(mechanism=raw_mechanism, payload=digest)

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
