"""Unit tests for PKCS#11 signing mechanism policy."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

import pytest

from crypto.adapters.pkcs11.capability_probe import (
    LibraryIdentity,
    MechanismCapability,
    Pkcs11Capabilities,
    TokenIdentity,
)
from crypto.adapters.pkcs11.mechanism_policy import resolve_signing_operation
from crypto.domain.algorithms import HashAlgorithmName, KeyAlgorithm, SignatureAlgorithm
from crypto.domain.errors import MechanismUnsupportedError
from crypto.domain.policies import SigningExecutionMode
from pkcs11 import Mechanism


@dataclass(frozen=True, slots=True)
class FakeSignRequest:
    signature_algorithm: SignatureAlgorithm
    hash_algorithm: HashAlgorithmName
    prehashed: bool = False


def _capabilities(*mechanisms: Mechanism) -> Pkcs11Capabilities:
    return Pkcs11Capabilities(
        pkcs11_spec_version='3.1',
        library=LibraryIdentity(description='Test', manufacturer='Test', version='1.0'),
        token=TokenIdentity(
            slot_id=1,
            label='Test Token',
            serial='ABC123',
            model='Test',
            manufacturer='Test',
            hardware_version='1.0',
            firmware_version='1.0',
        ),
        token_flags=(),
        mechanisms={
            f'CKM_{mechanism.name}': MechanismCapability(
                name=f'CKM_{mechanism.name}',
                code=int(mechanism),
                flags=('SIGN',),
            )
            for mechanism in mechanisms
        },
        derived_features={},
    )


def test_resolves_exact_rsa_pkcs1v15_sha256_mechanism_for_COMPLETE_BACKEND_mode() -> None:
    request = FakeSignRequest(
        signature_algorithm=SignatureAlgorithm.RSA_PKCS1V15,
        hash_algorithm=HashAlgorithmName.SHA256,
        prehashed=False,
    )
    payload = b'hello world'
    capabilities = _capabilities(Mechanism.SHA256_RSA_PKCS)

    operation = resolve_signing_operation(
        key_algorithm=KeyAlgorithm.RSA,
        data=payload,
        request=request,
        capabilities=capabilities,
        signing_execution_mode=SigningExecutionMode.COMPLETE_BACKEND,
    )

    assert operation.mechanism is Mechanism.SHA256_RSA_PKCS
    assert operation.payload == payload


def test_rejects_rsa_raw_pkcs_only_in_COMPLETE_BACKEND_mode() -> None:
    request = FakeSignRequest(
        signature_algorithm=SignatureAlgorithm.RSA_PKCS1V15,
        hash_algorithm=HashAlgorithmName.SHA256,
        prehashed=False,
    )
    capabilities = _capabilities(Mechanism.RSA_PKCS)

    with pytest.raises(MechanismUnsupportedError):
        resolve_signing_operation(
            key_algorithm=KeyAlgorithm.RSA,
            data=b'hello world',
            request=request,
            capabilities=capabilities,
            signing_execution_mode=SigningExecutionMode.COMPLETE_BACKEND,
        )


def test_resolves_rsa_raw_pkcs_for_ALLOW_APPLICATION_HASH_mode() -> None:
    request = FakeSignRequest(
        signature_algorithm=SignatureAlgorithm.RSA_PKCS1V15,
        hash_algorithm=HashAlgorithmName.SHA256,
        prehashed=False,
    )
    payload = b'hello world'
    capabilities = _capabilities(Mechanism.RSA_PKCS)

    operation = resolve_signing_operation(
        key_algorithm=KeyAlgorithm.RSA,
        data=payload,
        request=request,
        capabilities=capabilities,
        signing_execution_mode=SigningExecutionMode.ALLOW_APPLICATION_HASH,
    )

    assert operation.mechanism is Mechanism.RSA_PKCS
    assert operation.payload.startswith(bytes.fromhex('3031300d060960864801650304020105000420'))
    assert operation.payload.endswith(hashlib.sha256(payload).digest())


def test_resolves_exact_ecdsa_sha256_mechanism_for_COMPLETE_BACKEND_mode() -> None:
    request = FakeSignRequest(
        signature_algorithm=SignatureAlgorithm.ECDSA,
        hash_algorithm=HashAlgorithmName.SHA256,
        prehashed=False,
    )
    payload = b'hello world'
    capabilities = _capabilities(Mechanism.ECDSA_SHA256)

    operation = resolve_signing_operation(
        key_algorithm=KeyAlgorithm.EC,
        data=payload,
        request=request,
        capabilities=capabilities,
        signing_execution_mode=SigningExecutionMode.COMPLETE_BACKEND,
    )

    assert operation.mechanism is Mechanism.ECDSA_SHA256
    assert operation.payload == payload


def test_rejects_raw_ecdsa_only_in_COMPLETE_BACKEND_mode() -> None:
    request = FakeSignRequest(
        signature_algorithm=SignatureAlgorithm.ECDSA,
        hash_algorithm=HashAlgorithmName.SHA256,
        prehashed=False,
    )
    capabilities = _capabilities(Mechanism.ECDSA)

    with pytest.raises(MechanismUnsupportedError):
        resolve_signing_operation(
            key_algorithm=KeyAlgorithm.EC,
            data=b'hello world',
            request=request,
            capabilities=capabilities,
            signing_execution_mode=SigningExecutionMode.COMPLETE_BACKEND,
        )


def test_resolves_raw_ecdsa_for_ALLOW_APPLICATION_HASH_mode() -> None:
    request = FakeSignRequest(
        signature_algorithm=SignatureAlgorithm.ECDSA,
        hash_algorithm=HashAlgorithmName.SHA256,
        prehashed=False,
    )
    payload = b'hello world'
    capabilities = _capabilities(Mechanism.ECDSA)

    operation = resolve_signing_operation(
        key_algorithm=KeyAlgorithm.EC,
        data=payload,
        request=request,
        capabilities=capabilities,
        signing_execution_mode=SigningExecutionMode.ALLOW_APPLICATION_HASH,
    )

    assert operation.mechanism is Mechanism.ECDSA
    assert operation.payload == hashlib.sha256(payload).digest()


def test_rejects_prehashed_managed_signing_requests() -> None:
    request = FakeSignRequest(
        signature_algorithm=SignatureAlgorithm.RSA_PKCS1V15,
        hash_algorithm=HashAlgorithmName.SHA256,
        prehashed=True,
    )
    capabilities = _capabilities(Mechanism.SHA256_RSA_PKCS)

    with pytest.raises(MechanismUnsupportedError):
        resolve_signing_operation(
            key_algorithm=KeyAlgorithm.RSA,
            data=b'already-digested',
            request=request,
            capabilities=capabilities,
            signing_execution_mode=SigningExecutionMode.COMPLETE_BACKEND,
        )
