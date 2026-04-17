"""Exact HSM-only PKCS#11 sign-operation resolution."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from crypto.adapters.pkcs11.mechanisms import ecdsa_mechanism_for_hash, rsa_pkcs1v15_mechanism_for_hash
from crypto.domain.algorithms import KeyAlgorithm, SignatureAlgorithm
from crypto.domain.errors import MechanismUnsupportedError
from pkcs11 import Mechanism

if TYPE_CHECKING:
    from crypto.adapters.pkcs11.capability_probe import Pkcs11Capabilities
    from crypto.domain.specs import SignRequest


@dataclass(frozen=True, slots=True)
class Pkcs11SignOperation:
    """Resolved exact PKCS#11 sign operation."""

    mechanism: Mechanism
    payload: bytes


def resolve_signing_operation(
    *,
    key_algorithm: KeyAlgorithm,
    data: bytes,
    request: SignRequest,
    capabilities: Pkcs11Capabilities,
) -> Pkcs11SignOperation:
    """Resolve an exact HSM-executed PKCS#11 sign operation.

    Security rule:
    - Trustpoint does not hash, pad, or transform signing payloads in software
      for managed-key application signing.
    - The selected PKCS#11 mechanism must represent the complete in-HSM sign
      operation requested by the caller.
    """
    if request.prehashed:
        msg = (
            'Managed PKCS#11 signing does not accept prehashed payloads. '
            'Trustpoint requires the HSM to perform the complete signing operation.'
        )
        raise MechanismUnsupportedError(msg)

    if key_algorithm is KeyAlgorithm.RSA:
        return _resolve_rsa_signing_operation(data=data, request=request, capabilities=capabilities)

    if key_algorithm is KeyAlgorithm.EC:
        return _resolve_ec_signing_operation(data=data, request=request, capabilities=capabilities)

    msg = f'Unsupported key algorithm for signing: {key_algorithm!r}'
    raise MechanismUnsupportedError(msg)


def _resolve_rsa_signing_operation(
    *,
    data: bytes,
    request: SignRequest,
    capabilities: Pkcs11Capabilities,
) -> Pkcs11SignOperation:
    """Resolve an exact HSM-only RSA sign operation."""
    if request.signature_algorithm is not SignatureAlgorithm.RSA_PKCS1V15:
        msg = f'Unsupported RSA signature algorithm: {request.signature_algorithm.value}'
        raise MechanismUnsupportedError(msg)

    mechanism = rsa_pkcs1v15_mechanism_for_hash(request.hash_algorithm)
    if not capabilities.supports(mechanism):
        msg = (
            f'Token does not support the exact in-HSM PKCS#11 mechanism {mechanism.name} '
            f'for {request.signature_algorithm.value} with {request.hash_algorithm.value}. '
            'Trustpoint does not apply software hashing or padding fallbacks for managed keys.'
        )
        raise MechanismUnsupportedError(msg)

    return Pkcs11SignOperation(mechanism=mechanism, payload=data)


def _resolve_ec_signing_operation(
    *,
    data: bytes,
    request: SignRequest,
    capabilities: Pkcs11Capabilities,
) -> Pkcs11SignOperation:
    """Resolve an exact HSM-only EC sign operation."""
    if request.signature_algorithm is not SignatureAlgorithm.ECDSA:
        msg = f'Unsupported EC signature algorithm: {request.signature_algorithm.value}'
        raise MechanismUnsupportedError(msg)

    mechanism = ecdsa_mechanism_for_hash(request.hash_algorithm)
    if not capabilities.supports(mechanism):
        msg = (
            f'Token does not support the exact in-HSM PKCS#11 mechanism {mechanism.name} '
            f'for {request.signature_algorithm.value} with {request.hash_algorithm.value}. '
            'Trustpoint does not apply software hashing fallbacks for managed keys.'
        )
        raise MechanismUnsupportedError(msg)

    return Pkcs11SignOperation(mechanism=mechanism, payload=data)
