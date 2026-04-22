"""Tests for managed-key persistence helpers."""

from __future__ import annotations

import pytest
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from crypto.adapters.pkcs11.bindings import Pkcs11ManagedKeyBinding
from crypto.domain.algorithms import KeyAlgorithm
from crypto.domain.policies import KeyPolicy, SigningExecutionMode
from crypto.models import (
    CryptoManagedKeyModel,
    CryptoProviderProfileModel,
    ManagedKeyStatus,
    ProviderAuthSource,
)
from crypto.repositories import CryptoManagedKeyRepository


@pytest.mark.django_db
def test_create_managed_key_persists_binding() -> None:
    profile = CryptoProviderProfileModel.objects.create(
        name='provider-1',
        module_path='/usr/lib/test-pkcs11.so',
        token_serial='1234',
        auth_source=ProviderAuthSource.FILE,
        auth_source_ref='/tmp/user-pin.txt',
        active=True,
    )
    public_key = rsa.generate_private_key(public_exponent=65537, key_size=2048).public_key()
    binding = Pkcs11ManagedKeyBinding(
        key_id=b'\x01\x02\x03\x04',
        algorithm=KeyAlgorithm.RSA,
        signing_execution_mode=SigningExecutionMode.ALLOW_SOFTWARE_HASH,
    )

    repo = CryptoManagedKeyRepository()
    managed_key = repo.create_managed_key(
        profile=profile,
        alias='ca/root',
        binding=binding,
        public_key=public_key,
        policy=KeyPolicy.managed_signing_key(signing_execution_mode=SigningExecutionMode.ALLOW_SOFTWARE_HASH),
    )

    assert managed_key.alias == 'ca/root'
    assert managed_key.provider_profile_id == profile.pk
    assert managed_key.key_id_hex == '01020304'
    assert managed_key.algorithm == 'rsa'
    assert managed_key.signing_execution_mode == SigningExecutionMode.ALLOW_SOFTWARE_HASH.value
    assert managed_key.status == ManagedKeyStatus.ACTIVE
    assert len(managed_key.public_key_fingerprint_sha256) == 64
    assert managed_key.policy_snapshot['extractable'] is False
    assert managed_key.policy_snapshot['ephemeral'] is False
    assert managed_key.policy_snapshot['signing_execution_mode'] == SigningExecutionMode.ALLOW_SOFTWARE_HASH.value
    assert 'sign' in managed_key.policy_snapshot['usages']


@pytest.mark.django_db
def test_build_managed_key_ref_round_trips() -> None:
    profile = CryptoProviderProfileModel.objects.create(
        name='provider-1',
        module_path='/usr/lib/test-pkcs11.so',
        token_serial='1234',
        auth_source=ProviderAuthSource.FILE,
        auth_source_ref='/tmp/user-pin.txt',
        active=True,
    )
    managed_key = CryptoManagedKeyModel.objects.create(
        alias='signer/ec',
        provider_profile=profile,
        key_id_hex='0a0b0c0d',
        label='signer/ec',
        algorithm='ec',
        public_key_fingerprint_sha256='a' * 64,
        signing_execution_mode=SigningExecutionMode.ALLOW_SOFTWARE_HASH.value,
        policy_snapshot={'extractable': False, 'ephemeral': False, 'usages': ['sign', 'verify']},
    )

    key_ref = managed_key.to_managed_key_ref()

    assert key_ref.id == managed_key.id
    assert key_ref.alias == 'signer/ec'
    assert key_ref.algorithm is KeyAlgorithm.EC
    assert key_ref.public_key_fingerprint_sha256 == 'a' * 64
    assert key_ref.signing_execution_mode is SigningExecutionMode.ALLOW_SOFTWARE_HASH


@pytest.mark.django_db
def test_mark_missing_sets_status_and_error() -> None:
    profile = CryptoProviderProfileModel.objects.create(
        name='provider-1',
        module_path='/usr/lib/test-pkcs11.so',
        token_serial='1234',
        auth_source=ProviderAuthSource.FILE,
        auth_source_ref='/tmp/user-pin.txt',
        active=True,
    )
    managed_key = CryptoManagedKeyModel.objects.create(
        alias='ca/root',
        provider_profile=profile,
        key_id_hex='01020304',
        label='ca/root',
        algorithm='rsa',
        public_key_fingerprint_sha256='b' * 64,
        signing_execution_mode=SigningExecutionMode.COMPLETE_HSM.value,
        policy_snapshot={'extractable': False, 'ephemeral': False, 'usages': ['sign']},
    )

    repo = CryptoManagedKeyRepository()
    repo.mark_missing(managed_key=managed_key, error_summary='key not found on token')
    managed_key.refresh_from_db()

    assert managed_key.status == ManagedKeyStatus.MISSING
    assert managed_key.last_verification_error == 'key not found on token'
    assert managed_key.last_verified_at is not None


@pytest.mark.django_db
def test_public_key_fingerprint_is_stable() -> None:
    public_key = ec.generate_private_key(ec.SECP256R1()).public_key()

    repo = CryptoManagedKeyRepository()
    fp1 = repo.public_key_fingerprint_sha256(public_key)
    fp2 = repo.public_key_fingerprint_sha256(public_key)

    assert fp1 == fp2
    assert len(fp1) == 64
