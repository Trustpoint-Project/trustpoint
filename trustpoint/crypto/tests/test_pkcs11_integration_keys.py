"""Live managed-key tests against a configured PKCS#11 provider."""

from __future__ import annotations

import secrets

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

from crypto.domain.policies import KeyPolicy, KeyUsage
from crypto.domain.specs import RsaKeySpec, SignRequest


pytestmark = [pytest.mark.integration, pytest.mark.hsm, pytest.mark.django_db]


def test_generate_rsa_managed_key_and_fetch_public_key(live_pkcs11_backend) -> None:
    alias = f"pytest-rsa-{secrets.token_hex(6)}"
    key = live_pkcs11_backend.generate_managed_key(
        alias=alias,
        key_spec=RsaKeySpec(key_size=2048),
        policy=KeyPolicy(
            usages=frozenset({KeyUsage.SIGN}),
            extractable=False,
            ephemeral=False,
        ),
    )

    public_key = live_pkcs11_backend.get_public_key(key)
    assert public_key is not None


def test_sign_with_generated_rsa_key_and_verify_signature(live_pkcs11_backend) -> None:
    alias = f"pytest-sign-{secrets.token_hex(6)}"
    key = live_pkcs11_backend.generate_managed_key(
        alias=alias,
        key_spec=RsaKeySpec(key_size=2048),
        policy=KeyPolicy(
            usages=frozenset({KeyUsage.SIGN}),
            extractable=False,
            ephemeral=False,
        ),
    )

    payload = b"trustpoint-pkcs11-test"
    signature = live_pkcs11_backend.sign(
        key=key,
        data=payload,
        request=SignRequest.rsa_pkcs1v15_sha256(),
    )

    assert isinstance(signature, bytes)
    assert signature

    public_key = live_pkcs11_backend.get_public_key(key)
    public_key.verify(
        signature,
        payload,
        padding.PKCS1v15(),
        hashes.SHA256(),
    )
