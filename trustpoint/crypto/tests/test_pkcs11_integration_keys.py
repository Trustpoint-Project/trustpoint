"""Live managed-key tests against a configured PKCS#11 provider."""

from __future__ import annotations

import secrets

import pytest

from crypto.domain.algorithms import HashAlgorithmName, SignatureAlgorithm
from crypto.domain.policies import KeyPolicy, KeyUsage
from crypto.domain.specs import RsaKeySpec, SignRequest


pytestmark = [pytest.mark.integration, pytest.mark.hsm, pytest.mark.django_db]


def test_generate_rsa_managed_key_and_fetch_public_key(live_pkcs11_backend) -> None:
    alias = f"pytest-rsa-{secrets.token_hex(6)}"
    key = live_pkcs11_backend.generate_managed_key(
        alias=alias,
        key_spec=RsaKeySpec(key_size=2048),
        policy=KeyPolicy(
            usages={KeyUsage.SIGN},
            extractable=False,
            ephemeral=False,
        ),
    )

    public_key = live_pkcs11_backend.get_public_key(key)
    assert public_key is not None


def test_sign_with_generated_rsa_key(live_pkcs11_backend) -> None:
    alias = f"pytest-sign-{secrets.token_hex(6)}"
    key = live_pkcs11_backend.generate_managed_key(
        alias=alias,
        key_spec=RsaKeySpec(key_size=2048),
        policy=KeyPolicy(
            usages={KeyUsage.SIGN},
            extractable=False,
            ephemeral=False,
        ),
    )

    signature = live_pkcs11_backend.sign(
        key=key,
        data=b"trustpoint-pkcs11-test",
        request=SignRequest(
            signature_algorithm=SignatureAlgorithm.RSA_PKCS1V15,
            hash_algorithm=HashAlgorithmName.SHA256,
            prehashed=False,
        ),
    )

    assert isinstance(signature, bytes)
    assert signature
