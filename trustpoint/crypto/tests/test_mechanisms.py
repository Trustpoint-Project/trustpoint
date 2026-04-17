"""Unit tests for exact HSM-only PKCS#11 mechanism selection."""

from __future__ import annotations

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


def test_resolves_exact_rsa_pkcs1v15_sha256_mechanism() -> None:
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
    )

    assert operation.mechanism is Mechanism.SHA256_RSA_PKCS
    assert operation.payload == payload


def test_rejects_rsa_raw_pkcs_only_when_exact_hash_sign_mechanism_is_missing() -> None:
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
        )


def test_resolves_exact_ecdsa_sha256_mechanism() -> None:
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
    )

    assert operation.mechanism is Mechanism.ECDSA_SHA256
    assert operation.payload == payload


def test_rejects_raw_ecdsa_only_when_exact_hash_sign_mechanism_is_missing() -> None:
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
        )


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
        )
