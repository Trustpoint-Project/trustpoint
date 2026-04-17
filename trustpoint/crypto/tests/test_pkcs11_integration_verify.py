"""Live managed-key verification tests against a configured PKCS#11 provider."""

from __future__ import annotations

import secrets
from dataclasses import replace

import pytest

from crypto.domain.algorithms import KeyAlgorithm
from crypto.domain.policies import KeyPolicy, KeyUsage
from crypto.domain.refs import (
    ManagedKeyRef,
    ManagedKeyVerificationStatus,
)
from crypto.domain.specs import RsaKeySpec


pytestmark = [pytest.mark.integration, pytest.mark.hsm, pytest.mark.django_db]


def test_verify_managed_key_reports_present_for_fresh_key(live_pkcs11_backend) -> None:
    alias = f"pytest-verify-{secrets.token_hex(6)}"
    key = live_pkcs11_backend.generate_managed_key(
        alias=alias,
        key_spec=RsaKeySpec(key_size=2048),
        policy=KeyPolicy(
            usages=frozenset({KeyUsage.SIGN}),
            extractable=False,
            ephemeral=False,
        ),
    )

    assert key.public_key_fingerprint_sha256 is not None

    verification = live_pkcs11_backend.verify_managed_key(key)

    assert verification.status is ManagedKeyVerificationStatus.PRESENT
    assert verification.resolved_public_key_fingerprint_sha256 == key.public_key_fingerprint_sha256
    assert verification.is_present is True


def test_verify_managed_key_reports_mismatch_for_wrong_fingerprint(live_pkcs11_backend) -> None:
    alias = f"pytest-mismatch-{secrets.token_hex(6)}"
    key = live_pkcs11_backend.generate_managed_key(
        alias=alias,
        key_spec=RsaKeySpec(key_size=2048),
        policy=KeyPolicy(
            usages=frozenset({KeyUsage.SIGN}),
            extractable=False,
            ephemeral=False,
        ),
    )

    tampered = replace(
        key,
        public_key_fingerprint_sha256='00' * 32,
    )

    verification = live_pkcs11_backend.verify_managed_key(tampered)

    assert verification.status is ManagedKeyVerificationStatus.MISMATCH
    assert verification.resolved_public_key_fingerprint_sha256 is not None
    assert verification.resolved_public_key_fingerprint_sha256 != tampered.public_key_fingerprint_sha256
    assert verification.is_present is False


def test_verify_managed_key_reports_missing_for_unknown_key(live_pkcs11_backend) -> None:
    alias = f"pytest-missing-{secrets.token_hex(6)}"
    missing = ManagedKeyRef(
        alias=alias,
        provider='pkcs11',
        key_id=secrets.token_bytes(16),
        label=alias,
        algorithm=KeyAlgorithm.RSA,
        public_key_fingerprint_sha256='11' * 32,
    )

    verification = live_pkcs11_backend.verify_managed_key(missing)

    assert verification.status is ManagedKeyVerificationStatus.MISSING
    assert verification.resolved_public_key_fingerprint_sha256 is None
    assert verification.is_present is False
