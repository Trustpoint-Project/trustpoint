"""Tests for the application-facing crypto backend."""

from __future__ import annotations

from dataclasses import dataclass, field

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from crypto.adapters.pkcs11.bindings import (
    Pkcs11ManagedKeyBinding,
    Pkcs11ManagedKeyVerification,
)
from crypto.application.service import TrustpointCryptoBackend
from crypto.domain.algorithms import KeyAlgorithm
from crypto.domain.policies import KeyPolicy, SigningExecutionMode
from crypto.domain.refs import ManagedKeyVerificationStatus
from crypto.domain.specs import RsaKeySpec, SignRequest
from crypto.models import (
    CryptoManagedKeyModel,
    CryptoProviderProfileModel,
    ManagedKeyStatus,
    ProviderAuthSource,
)


@dataclass
class FakeAdapter:
    """Minimal PKCS#11 adapter fake for application-backend tests."""

    public_key: object
    generated_binding: Pkcs11ManagedKeyBinding
    signature: bytes = b'signature'
    verification: Pkcs11ManagedKeyVerification = field(
        default_factory=lambda: Pkcs11ManagedKeyVerification(
            status=ManagedKeyVerificationStatus.PRESENT,
            resolved_public_key_fingerprint_sha256=None,
        )
    )
    generate_calls: list[tuple[str, object, object]] = field(default_factory=list)
    get_public_key_calls: list[Pkcs11ManagedKeyBinding] = field(default_factory=list)
    sign_calls: list[tuple[Pkcs11ManagedKeyBinding, bytes, SignRequest]] = field(default_factory=list)
    verify_calls: list[Pkcs11ManagedKeyBinding] = field(default_factory=list)
    destroy_calls: list[Pkcs11ManagedKeyBinding] = field(default_factory=list)
    close_calls: int = 0

    def verify_provider(self) -> None:
        """Satisfy the application backend contract."""

    def generate_managed_key(self, *, alias: str, key_spec: object, policy: object) -> Pkcs11ManagedKeyBinding:
        """Return the configured binding and record the generation request."""
        self.generate_calls.append((alias, key_spec, policy))
        return self.generated_binding

    def get_public_key(self, key: Pkcs11ManagedKeyBinding) -> object:
        """Return the configured public key."""
        self.get_public_key_calls.append(key)
        return self.public_key

    def sign(self, *, key: Pkcs11ManagedKeyBinding, data: bytes, request: SignRequest) -> bytes:
        """Return the configured signature."""
        self.sign_calls.append((key, data, request))
        return self.signature

    def verify_managed_key(self, key: Pkcs11ManagedKeyBinding) -> Pkcs11ManagedKeyVerification:
        """Return the configured verification result."""
        self.verify_calls.append(key)
        return self.verification

    def destroy_managed_key(self, key: Pkcs11ManagedKeyBinding) -> None:
        """Record cleanup requests."""
        self.destroy_calls.append(key)

    def close(self) -> None:
        """Track close calls."""
        self.close_calls += 1


@pytest.mark.django_db
def test_generate_managed_key_persists_opaque_ref_and_signing_mode() -> None:
    profile = CryptoProviderProfileModel.objects.create(
        name='provider-1',
        module_path='/usr/lib/test-pkcs11.so',
        token_serial='1234',
        auth_source=ProviderAuthSource.FILE,
        auth_source_ref='/tmp/user-pin.txt',
        active=True,
    )
    public_key = rsa.generate_private_key(public_exponent=65537, key_size=2048).public_key()
    adapter = FakeAdapter(
        public_key=public_key,
        generated_binding=Pkcs11ManagedKeyBinding(
            key_id=b'\x01\x02\x03\x04',
            algorithm=KeyAlgorithm.RSA,
            signing_execution_mode=SigningExecutionMode.ALLOW_SOFTWARE_HASH,
        ),
    )
    backend = TrustpointCryptoBackend(adapter_factory=lambda _profile: adapter)

    key_ref = backend.generate_managed_key(
        alias='ca/root',
        key_spec=RsaKeySpec(key_size=2048),
        policy=KeyPolicy.managed_signing_key(signing_execution_mode=SigningExecutionMode.ALLOW_SOFTWARE_HASH),
    )

    managed_key = CryptoManagedKeyModel.objects.get(pk=key_ref.id)
    assert managed_key.provider_profile_id == profile.pk
    assert key_ref.alias == 'ca/root'
    assert key_ref.algorithm is KeyAlgorithm.RSA
    assert key_ref.public_key_fingerprint_sha256 == managed_key.public_key_fingerprint_sha256
    assert key_ref.signing_execution_mode is SigningExecutionMode.ALLOW_SOFTWARE_HASH
    assert managed_key.signing_execution_mode == SigningExecutionMode.ALLOW_SOFTWARE_HASH.value
    assert adapter.get_public_key_calls == [adapter.generated_binding]
    assert adapter.close_calls == 1


@pytest.mark.django_db
def test_sign_routes_through_persisted_pkcs11_binding() -> None:
    profile = CryptoProviderProfileModel.objects.create(
        name='provider-1',
        module_path='/usr/lib/test-pkcs11.so',
        token_serial='1234',
        auth_source=ProviderAuthSource.FILE,
        auth_source_ref='/tmp/user-pin.txt',
        active=True,
    )
    public_key = rsa.generate_private_key(public_exponent=65537, key_size=2048).public_key()
    adapter = FakeAdapter(
        public_key=public_key,
        generated_binding=Pkcs11ManagedKeyBinding(
            key_id=b'\xaa\xbb\xcc\xdd',
            algorithm=KeyAlgorithm.RSA,
            signing_execution_mode=SigningExecutionMode.ALLOW_SOFTWARE_HASH,
        ),
        signature=b'app-signature',
    )
    managed_key = CryptoManagedKeyModel.objects.create(
        alias='signer/rsa',
        provider_profile=profile,
        key_id_hex='aabbccdd',
        label='signer/rsa',
        algorithm='rsa',
        public_key_fingerprint_sha256='b' * 64,
        signing_execution_mode=SigningExecutionMode.ALLOW_SOFTWARE_HASH.value,
        policy_snapshot={'extractable': False, 'ephemeral': False, 'usages': ['sign', 'verify']},
    )
    backend = TrustpointCryptoBackend(adapter_factory=lambda _profile: adapter)

    signature = backend.sign(
        key=managed_key.to_managed_key_ref(),
        data=b'payload',
        request=SignRequest.rsa_pkcs1v15_sha256(),
    )

    assert signature == b'app-signature'
    binding, payload, request = adapter.sign_calls[0]
    assert binding.key_id == bytes.fromhex('aabbccdd')
    assert binding.signing_execution_mode is SigningExecutionMode.ALLOW_SOFTWARE_HASH
    assert payload == b'payload'
    assert request.signature_algorithm is SignRequest.rsa_pkcs1v15_sha256().signature_algorithm


@pytest.mark.django_db
def test_verify_managed_key_updates_repository_status() -> None:
    profile = CryptoProviderProfileModel.objects.create(
        name='provider-1',
        module_path='/usr/lib/test-pkcs11.so',
        token_serial='1234',
        auth_source=ProviderAuthSource.FILE,
        auth_source_ref='/tmp/user-pin.txt',
        active=True,
    )
    public_key = rsa.generate_private_key(public_exponent=65537, key_size=2048).public_key()
    adapter = FakeAdapter(
        public_key=public_key,
        generated_binding=Pkcs11ManagedKeyBinding(
            key_id=b'\xaa\xbb\xcc\xdd',
            algorithm=KeyAlgorithm.RSA,
        ),
        verification=Pkcs11ManagedKeyVerification(
            status=ManagedKeyVerificationStatus.MISMATCH,
            resolved_public_key_fingerprint_sha256='c' * 64,
        ),
    )
    managed_key = CryptoManagedKeyModel.objects.create(
        alias='verify/rsa',
        provider_profile=profile,
        key_id_hex='aabbccdd',
        label='verify/rsa',
        algorithm='rsa',
        public_key_fingerprint_sha256='b' * 64,
        signing_execution_mode=SigningExecutionMode.COMPLETE_HSM.value,
        policy_snapshot={'extractable': False, 'ephemeral': False, 'usages': ['sign', 'verify']},
    )
    backend = TrustpointCryptoBackend(adapter_factory=lambda _profile: adapter)

    verification = backend.verify_managed_key(managed_key.to_managed_key_ref())

    managed_key.refresh_from_db()
    assert verification.status is ManagedKeyVerificationStatus.MISMATCH
    assert verification.key.id == managed_key.id
    assert managed_key.status == ManagedKeyStatus.MISMATCH
    assert managed_key.last_verification_error == 'Managed key binding resolved to a different public key.'
