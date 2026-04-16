"""Unit tests for PKCS#11 mechanism selection."""

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
from crypto.adapters.pkcs11.mechanisms import signing_operation_for_request
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


def test_rsa_prefers_raw_pkcs_when_available() -> None:
    request = FakeSignRequest(
        signature_algorithm=SignatureAlgorithm.RSA_PKCS1V15,
        hash_algorithm=HashAlgorithmName.SHA256,
        prehashed=False,
    )
    payload = b'hello world'
    capabilities = _capabilities(Mechanism.RSA_PKCS, Mechanism.SHA256_RSA_PKCS)

    operation = signing_operation_for_request(
        key_algorithm=KeyAlgorithm.RSA,
        data=payload,
        request=request,
        capabilities=capabilities,
    )

    assert operation.mechanism is Mechanism.RSA_PKCS
    assert operation.payload.startswith(bytes.fromhex('3031300d060960864801650304020105000420'))
    assert operation.payload.endswith(hashlib.sha256(payload).digest())


def test_rsa_falls_back_to_combined_mechanism_when_raw_pkcs_is_missing() -> None:
    request = FakeSignRequest(
        signature_algorithm=SignatureAlgorithm.RSA_PKCS1V15,
        hash_algorithm=HashAlgorithmName.SHA256,
        prehashed=False,
    )
    payload = b'hello world'
    capabilities = _capabilities(Mechanism.SHA256_RSA_PKCS)

    operation = signing_operation_for_request(
        key_algorithm=KeyAlgorithm.RSA,
        data=payload,
        request=request,
        capabilities=capabilities,
    )

    assert operation.mechanism is Mechanism.SHA256_RSA_PKCS
    assert operation.payload == payload


def test_ecdsa_prefers_raw_ecdsa_when_available() -> None:
    request = FakeSignRequest(
        signature_algorithm=SignatureAlgorithm.ECDSA,
        hash_algorithm=HashAlgorithmName.SHA256,
        prehashed=False,
    )
    payload = b'hello world'
    capabilities = _capabilities(Mechanism.ECDSA, Mechanism.ECDSA_SHA256)

    operation = signing_operation_for_request(
        key_algorithm=KeyAlgorithm.EC,
        data=payload,
        request=request,
        capabilities=capabilities,
    )

    assert operation.mechanism is Mechanism.ECDSA
    assert operation.payload == hashlib.sha256(payload).digest()


def test_raises_when_no_supported_rsa_mechanism_exists() -> None:
    request = FakeSignRequest(
        signature_algorithm=SignatureAlgorithm.RSA_PKCS1V15,
        hash_algorithm=HashAlgorithmName.SHA256,
        prehashed=False,
    )
    capabilities = _capabilities()

    with pytest.raises(MechanismUnsupportedError):
        signing_operation_for_request(
            key_algorithm=KeyAlgorithm.RSA,
            data=b'hello world',
            request=request,
            capabilities=capabilities,
        )
