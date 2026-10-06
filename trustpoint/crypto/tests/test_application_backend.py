# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Tests for the application-facing crypto backend."""

from __future__ import annotations

from dataclasses import dataclass, field
from unittest.mock import patch

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from appsecrets.models import AppSecretBackendKind, AppSecretBackendModel
from crypto.adapters.pkcs11.bindings import (
    Pkcs11ManagedKeyBinding,
    Pkcs11ManagedKeyVerification,
)
from crypto.adapters.software.backend import SoftwareBackend
from crypto.application.service import TrustpointCryptoBackend
from crypto.domain.algorithms import KeyAlgorithm
from crypto.domain.errors import AuthenticationError, ProviderConfigurationError, ProviderOperationNotImplementedError
from crypto.domain.policies import KeyPolicy, SigningExecutionMode
from crypto.domain.refs import ManagedKeyVerificationStatus
from crypto.domain.specs import RsaKeySpec, SignRequest
from crypto.models import (
    BackendKind,
    CryptoManagedKeyModel,
    CryptoManagedKeyPkcs11BindingModel,
    CryptoManagedKeyProtectedImportBindingModel,
    CryptoProviderPkcs11ConfigModel,
    CryptoProviderProfileModel,
    CryptoProviderSoftwareConfigModel,
    ManagedKeyStatus,
    Pkcs11AuthSource,
    SoftwareKeyEncryptionSource,
)
from management.models import AuditLog, LoggingConfig, SecurityConfig
from pki.models.credential import CredentialModel


@pytest.fixture
def export_profile(monkeypatch: pytest.MonkeyPatch) -> CryptoProviderProfileModel:
    """Configure the real software backend with protected encryption material."""
    monkeypatch.setenv('TRUSTPOINT_TEST_TLS_KEY_SECRET', 'test-only-encryption-material')
    profile = CryptoProviderProfileModel.objects.create(
        name='tls-export', backend_kind=BackendKind.SOFTWARE, active=True,
    )
    CryptoProviderSoftwareConfigModel.objects.create(
        profile=profile,
        encryption_source=SoftwareKeyEncryptionSource.ENV,
        encryption_source_ref='TRUSTPOINT_TEST_TLS_KEY_SECRET',
        allow_exportable_private_keys=True,
    )
    return profile


@pytest.mark.django_db
def test_export_private_key_pkcs8_matches_generated_key(export_profile: CryptoProviderProfileModel) -> None:
    """Export decrypts the persisted key rather than generating a replacement."""
    backend = TrustpointCryptoBackend()
    key = backend.generate_managed_key(
        alias='tls/server', key_spec=RsaKeySpec(key_size=2048),
        policy=KeyPolicy(extractable=True, signing_execution_mode=SigningExecutionMode.ALLOW_APPLICATION_HASH),
    )
    exported = backend.export_private_key_pkcs8(key)
    private_key = serialization.load_pem_private_key(exported, password=None)
    assert exported.startswith(b'-----BEGIN PRIVATE KEY-----')
    assert private_key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo,
    ) == backend.get_public_key(key).public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    managed_key = CryptoManagedKeyModel.objects.get(pk=key.id)
    assert managed_key.provider_profile_id == export_profile.pk
    assert managed_key.policy_snapshot['extractable'] is True
    assert bytes(managed_key.software_binding.encrypted_private_key_pkcs8_der) != exported
    assert CryptoManagedKeyModel.objects.count() == 1


@pytest.mark.django_db
@pytest.mark.usefixtures('export_profile')
def test_export_private_key_pkcs8_rejects_nonextractable_key() -> None:
    """The default CA policy stays non-exportable even on an export-enabled provider."""
    backend = TrustpointCryptoBackend()
    key = backend.generate_managed_key(
        alias='ca/root', key_spec=RsaKeySpec(key_size=2048), policy=KeyPolicy.managed_signing_key(),
    )
    with pytest.raises(ProviderConfigurationError, match='not extractable'):
        backend.export_private_key_pkcs8(key)


@pytest.mark.django_db
def test_export_private_key_pkcs8_rejects_provider_policy(export_profile: CryptoProviderProfileModel) -> None:
    """A key opt-in cannot override the provider's export restriction."""
    backend = TrustpointCryptoBackend()
    key = backend.generate_managed_key(
        alias='tls/server', key_spec=RsaKeySpec(key_size=2048), policy=KeyPolicy(extractable=True),
    )
    config = export_profile.software_config
    config.allow_exportable_private_keys = False
    config.save(update_fields=['allow_exportable_private_keys'])
    with pytest.raises(ProviderConfigurationError, match='does not allow private-key export'):
        backend.export_private_key_pkcs8(key)


@pytest.mark.django_db
@pytest.mark.parametrize('backend_kind', [BackendKind.PKCS11, BackendKind.REST])
def test_export_private_key_pkcs8_rejects_unsupported_backend(backend_kind: str) -> None:
    """Non-software providers have no safe deployment export contract."""
    profile = CryptoProviderProfileModel.objects.create(name='unsupported-export', backend_kind=backend_kind)
    managed_key = CryptoManagedKeyModel.objects.create(
        alias='tls/unsupported', provider_profile=profile, algorithm='rsa',
        public_key_fingerprint_sha256='a' * 64, policy_snapshot={'extractable': True},
    )
    with pytest.raises(ProviderOperationNotImplementedError, match='only supported for software'):
        TrustpointCryptoBackend().export_private_key_pkcs8(managed_key.to_managed_key_ref())


@pytest.mark.django_db
@pytest.mark.usefixtures('export_profile')
def test_managed_tls_credential_serializer_exports_without_regenerating() -> None:
    """The activation serializer exports the persisted TLS key, but its wrapper cannot."""
    backend = TrustpointCryptoBackend()
    with patch.object(
        SoftwareBackend, 'generate_managed_key', autospec=True, side_effect=SoftwareBackend.generate_managed_key,
    ) as generate:
        key = backend.generate_managed_key(
            alias='tls/credential', key_spec=RsaKeySpec(key_size=2048),
            policy=KeyPolicy(extractable=True, signing_execution_mode=SigningExecutionMode.ALLOW_APPLICATION_HASH),
        )
        credential = CredentialModel.objects.create(
            credential_type=CredentialModel.CredentialTypeChoice.TRUSTPOINT_TLS_SERVER,
            managed_private_key_id=key.id,
        )
        credential.refresh_from_db()
        assert credential.private_key == ''
        assert credential.get_private_key_serializer().as_pkcs8_pem() == backend.export_private_key_pkcs8(key)
        assert generate.call_count == 1
    with pytest.raises(NotImplementedError, match='cannot be exported'):
        credential.get_private_key().private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption(),
        )


@pytest.mark.django_db
@pytest.mark.parametrize('credential_type', [
    CredentialModel.CredentialTypeChoice.ROOT_CA, CredentialModel.CredentialTypeChoice.ISSUING_CA,
])
@pytest.mark.usefixtures('export_profile')
def test_ca_credential_serializer_does_not_use_tls_export(credential_type: int) -> None:
    """Even an extractable key does not grant CA credentials the TLS serializer path."""
    key = TrustpointCryptoBackend().generate_managed_key(
        alias='ca/credential', key_spec=RsaKeySpec(key_size=2048), policy=KeyPolicy(extractable=True),
    )
    credential = CredentialModel.objects.create(credential_type=credential_type, managed_private_key_id=key.id)
    with patch.object(TrustpointCryptoBackend, 'export_private_key_pkcs8') as export:
        with pytest.raises((RuntimeError, NotImplementedError), match='cannot be exported'):
            credential.get_private_key_serializer().as_pkcs8_pem()
        export.assert_not_called()


@pytest.mark.django_db
@pytest.mark.usefixtures('export_profile')
def test_export_private_key_pkcs8_requires_encryption_secret(monkeypatch: pytest.MonkeyPatch) -> None:
    """Export still uses the configured secret resolver to unseal encrypted material."""
    backend = TrustpointCryptoBackend()
    key = backend.generate_managed_key(
        alias='tls/protected', key_spec=RsaKeySpec(key_size=2048), policy=KeyPolicy(extractable=True),
    )
    monkeypatch.delenv('TRUSTPOINT_TEST_TLS_KEY_SECRET')
    with pytest.raises(AuthenticationError, match='is missing'):
        backend.export_private_key_pkcs8(key)


@dataclass
class FakeAdapter:
    """Minimal backend adapter fake for application-backend tests."""

    public_key: object
    generated_binding: Pkcs11ManagedKeyBinding
    signature: bytes = b'signature'
    verification: Pkcs11ManagedKeyVerification = field(
        default_factory=lambda: Pkcs11ManagedKeyVerification(
            status=ManagedKeyVerificationStatus.PRESENT,
            resolved_public_key_fingerprint_sha256=None,
        )
    )
    verification_exception: Exception | None = None
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
        if self.verification_exception is not None:
            raise self.verification_exception
        return self.verification

    def destroy_managed_key(self, key: Pkcs11ManagedKeyBinding) -> None:
        """Record cleanup requests."""
        self.destroy_calls.append(key)

    def close(self) -> None:
        """Track close calls."""
        self.close_calls += 1


@dataclass
class FakeAdapterFactory:
    """Factory shim matching the new backend-factory contract."""

    adapter: FakeAdapter

    def build(self, _profile_model: CryptoProviderProfileModel) -> FakeAdapter:
        """Return the configured fake adapter."""
        return self.adapter


def _create_pkcs11_profile(*, name: str, active: bool = True) -> CryptoProviderProfileModel:
    """Create a generic provider profile plus PKCS#11 config."""
    profile = CryptoProviderProfileModel.objects.create(
        name=name,
        backend_kind=BackendKind.PKCS11,
        active=active,
    )
    CryptoProviderPkcs11ConfigModel.objects.create(
        profile=profile,
        module_path='/usr/lib/test-pkcs11.so',
        token_serial='1234',  # noqa: S106 - token serial test fixture, not a secret.
        token_label='',
        slot_id=None,
        auth_source=Pkcs11AuthSource.FILE,
        auth_source_ref='/tmp/user-pin.txt',  # noqa: S108 - test fixture path.
        max_sessions=4,
        borrow_timeout_seconds=2.0,
        rw_sessions=True,
    )
    return profile


def _create_software_profile(*, name: str, active: bool = True) -> CryptoProviderProfileModel:
    """Create a generic provider profile plus software config."""
    profile = CryptoProviderProfileModel.objects.create(
        name=name,
        backend_kind=BackendKind.SOFTWARE,
        active=active,
    )
    CryptoProviderSoftwareConfigModel.objects.create(
        profile=profile,
        encryption_source=SoftwareKeyEncryptionSource.DEV_PLAINTEXT,
        encryption_source_ref='',
        allow_exportable_private_keys=False,
    )
    return profile


def _backend_with_adapter(adapter: FakeAdapter) -> TrustpointCryptoBackend:
    """Build a backend service around the test adapter fake."""
    return TrustpointCryptoBackend(adapter_factory=FakeAdapterFactory(adapter=adapter))  # type: ignore[arg-type]


@pytest.mark.django_db
def test_generate_managed_key_persists_opaque_ref_and_signing_mode() -> None:
    """Managed-key generation persists an opaque backend reference and signing mode."""
    profile = _create_pkcs11_profile(name='provider-1', active=True)

    public_key = rsa.generate_private_key(public_exponent=65537, key_size=2048).public_key()
    adapter = FakeAdapter(
        public_key=public_key,
        generated_binding=Pkcs11ManagedKeyBinding(
            key_id=b'\x01\x02\x03\x04',
            algorithm=KeyAlgorithm.RSA,
            signing_execution_mode=SigningExecutionMode.ALLOW_APPLICATION_HASH,
        ),
    )
    backend = _backend_with_adapter(adapter)

    key_ref = backend.generate_managed_key(
        alias='ca/root',
        key_spec=RsaKeySpec(key_size=2048),
        policy=KeyPolicy.managed_signing_key(signing_execution_mode=SigningExecutionMode.ALLOW_APPLICATION_HASH),
    )

    managed_key = CryptoManagedKeyModel.objects.get(pk=key_ref.id)
    pkcs11_binding = CryptoManagedKeyPkcs11BindingModel.objects.get(managed_key=managed_key)

    assert managed_key.provider_profile_id == profile.pk
    assert managed_key.provider_label == 'ca/root'
    assert pkcs11_binding.key_id_hex == '01020304'
    assert key_ref.alias == 'ca/root'
    assert key_ref.algorithm is KeyAlgorithm.RSA
    assert key_ref.public_key_fingerprint_sha256 == managed_key.public_key_fingerprint_sha256
    assert key_ref.signing_execution_mode is SigningExecutionMode.ALLOW_APPLICATION_HASH
    assert managed_key.signing_execution_mode == SigningExecutionMode.ALLOW_APPLICATION_HASH.value
    assert adapter.get_public_key_calls == [adapter.generated_binding]
    assert adapter.close_calls == 1


@pytest.mark.django_db
def test_sign_routes_through_persisted_pkcs11_binding() -> None:
    """Signing resolves the persisted PKCS#11 binding and routes through the adapter."""
    profile = _create_pkcs11_profile(name='provider-1', active=True)

    public_key = rsa.generate_private_key(public_exponent=65537, key_size=2048).public_key()
    adapter = FakeAdapter(
        public_key=public_key,
        generated_binding=Pkcs11ManagedKeyBinding(
            key_id=b'\xaa\xbb\xcc\xdd',
            algorithm=KeyAlgorithm.RSA,
            signing_execution_mode=SigningExecutionMode.ALLOW_APPLICATION_HASH,
        ),
        signature=b'app-signature',
    )

    managed_key = CryptoManagedKeyModel.objects.create(
        alias='signer/rsa',
        provider_label='signer/rsa',
        provider_profile=profile,
        algorithm='rsa',
        public_key_fingerprint_sha256='b' * 64,
        signing_execution_mode=SigningExecutionMode.ALLOW_APPLICATION_HASH.value,
        policy_snapshot={'extractable': False, 'ephemeral': False, 'usages': ['sign', 'verify']},
    )
    CryptoManagedKeyPkcs11BindingModel.objects.create(
        managed_key=managed_key,
        provider_profile=profile,
        key_id_hex='aabbccdd',
    )

    backend = _backend_with_adapter(adapter)

    signature = backend.sign(
        key=managed_key.to_managed_key_ref(),
        data=b'payload',
        request=SignRequest.rsa_pkcs1v15_sha256(),
    )

    assert signature == b'app-signature'
    binding, payload, request = adapter.sign_calls[0]
    assert binding.key_id == bytes.fromhex('aabbccdd')
    assert binding.signing_execution_mode is SigningExecutionMode.ALLOW_APPLICATION_HASH
    assert binding.provider_label == 'signer/rsa'
    assert payload == b'payload'
    assert request.signature_algorithm is SignRequest.rsa_pkcs1v15_sha256().signature_algorithm


@pytest.mark.django_db
def test_imported_private_key_is_stored_as_protected_binding_and_signs_locally() -> None:
    """Imported private keys are protected by app-secret storage and routed through the backend API."""
    SecurityConfig.objects.update_or_create(
        pk=1,
        defaults={'allow_imported_private_keys': True},
    )
    profile = _create_pkcs11_profile(name='provider-1', active=True)
    AppSecretBackendModel.objects.update_or_create(
        singleton_id=AppSecretBackendModel.SINGLETON_ID,
        defaults={'backend_kind': AppSecretBackendKind.PKCS11},
    )
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    adapter = FakeAdapter(
        public_key=private_key.public_key(),
        generated_binding=Pkcs11ManagedKeyBinding(
            key_id=b'\x10\x20',
            algorithm=KeyAlgorithm.RSA,
        ),
    )
    backend = _backend_with_adapter(adapter)

    with (
        patch('crypto.application.service.get_app_secret_service') as mock_get_app_secret_service,
        patch('crypto.application.protected_import.encrypt_app_secret', side_effect=lambda value: value),
        patch('crypto.application.protected_import.decrypt_app_secret', side_effect=lambda value: value),
    ):
        mock_get_app_secret_service.return_value.ensure_backend_ready.return_value = None
        key_ref = backend.import_managed_private_key(
            alias='imported/issuing-ca',
            private_key=private_key,
            policy=KeyPolicy.managed_signing_key(
                signing_execution_mode=SigningExecutionMode.ALLOW_APPLICATION_HASH,
            ),
        )

        signature = backend.sign(
            key=key_ref,
            data=b'payload',
            request=SignRequest.rsa_pkcs1v15_sha256(),
        )
        resolved_public_key = backend.get_public_key(key_ref)

    managed_key = CryptoManagedKeyModel.objects.get(pk=key_ref.id)
    binding = CryptoManagedKeyProtectedImportBindingModel.objects.get(managed_key=managed_key)

    assert managed_key.provider_profile_id == profile.pk
    assert managed_key.alias == 'imported/issuing-ca'
    assert resolved_public_key.public_numbers() == private_key.public_key().public_numbers()
    assert binding.key_handle
    assert binding.encrypted_private_key_pkcs8_der_b64
    assert adapter.sign_calls == []
    private_key.public_key().verify(signature, b'payload', padding.PKCS1v15(), hashes.SHA256())


@pytest.mark.django_db
def test_imported_private_key_is_supported_with_software_backend() -> None:
    """Software-backed instances may import private keys when the explicit security policy allows it."""
    SecurityConfig.objects.update_or_create(
        pk=1,
        defaults={'allow_imported_private_keys': True},
    )
    profile = _create_software_profile(name='software-provider', active=True)
    AppSecretBackendModel.objects.update_or_create(
        singleton_id=AppSecretBackendModel.SINGLETON_ID,
        defaults={'backend_kind': AppSecretBackendKind.SOFTWARE},
    )
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    adapter = FakeAdapter(
        public_key=private_key.public_key(),
        generated_binding=Pkcs11ManagedKeyBinding(
            key_id=b'\x10\x20',
            algorithm=KeyAlgorithm.RSA,
        ),
    )
    backend = _backend_with_adapter(adapter)

    with (
        patch('crypto.application.service.get_app_secret_service') as mock_get_app_secret_service,
        patch('crypto.application.protected_import.encrypt_app_secret', side_effect=lambda value: value),
        patch('crypto.application.protected_import.decrypt_app_secret', side_effect=lambda value: value),
    ):
        mock_get_app_secret_service.return_value.ensure_backend_ready.return_value = None
        key_ref = backend.import_managed_private_key(
            alias='imported/software-ca',
            private_key=private_key,
            policy=KeyPolicy.managed_signing_key(
                signing_execution_mode=SigningExecutionMode.ALLOW_APPLICATION_HASH,
            ),
        )

        signature = backend.sign(
            key=key_ref,
            data=b'payload',
            request=SignRequest.rsa_pkcs1v15_sha256(),
        )

    managed_key = CryptoManagedKeyModel.objects.get(pk=key_ref.id)
    binding = CryptoManagedKeyProtectedImportBindingModel.objects.get(managed_key=managed_key)

    assert managed_key.provider_profile_id == profile.pk
    assert managed_key.alias == 'imported/software-ca'
    assert binding.provider_profile_id == profile.pk
    assert adapter.sign_calls == []
    private_key.public_key().verify(signature, b'payload', padding.PKCS1v15(), hashes.SHA256())


@pytest.mark.django_db
def test_imported_private_key_requires_security_setting() -> None:
    """Private-key imports fail closed unless the Security setting explicitly allows them."""
    _create_pkcs11_profile(name='provider-1', active=True)
    AppSecretBackendModel.objects.update_or_create(
        singleton_id=AppSecretBackendModel.SINGLETON_ID,
        defaults={'backend_kind': AppSecretBackendKind.PKCS11},
    )
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    adapter = FakeAdapter(
        public_key=private_key.public_key(),
        generated_binding=Pkcs11ManagedKeyBinding(
            key_id=b'\x10\x20',
            algorithm=KeyAlgorithm.RSA,
        ),
    )
    backend = _backend_with_adapter(adapter)

    with pytest.raises(ProviderConfigurationError, match='Imported private keys are disabled'):
        backend.import_managed_private_key(
            alias='imported/issuing-ca',
            private_key=private_key,
            policy=KeyPolicy.managed_signing_key(
                signing_execution_mode=SigningExecutionMode.ALLOW_APPLICATION_HASH,
            ),
        )


@pytest.mark.django_db
def test_crypto_backend_audit_records_sanitized_sign_operation_when_enabled() -> None:
    """Crypto backend audit stores metadata without payload or signature bytes."""
    profile = _create_pkcs11_profile(name='provider-1', active=True)
    LoggingConfig.objects.update_or_create(
        id=1,
        defaults={'log_level': 'INFO', 'crypto_backend_audit_enabled': True},
    )

    public_key = rsa.generate_private_key(public_exponent=65537, key_size=2048).public_key()
    adapter = FakeAdapter(
        public_key=public_key,
        generated_binding=Pkcs11ManagedKeyBinding(
            key_id=b'\xaa\xbb\xcc\xdd',
            algorithm=KeyAlgorithm.RSA,
            signing_execution_mode=SigningExecutionMode.ALLOW_APPLICATION_HASH,
        ),
        signature=b'app-signature',
    )

    managed_key = CryptoManagedKeyModel.objects.create(
        alias='signer/rsa',
        provider_label='signer/rsa',
        provider_profile=profile,
        algorithm='rsa',
        public_key_fingerprint_sha256='b' * 64,
        signing_execution_mode=SigningExecutionMode.ALLOW_APPLICATION_HASH.value,
        policy_snapshot={'extractable': False, 'ephemeral': False, 'usages': ['sign', 'verify']},
    )
    CryptoManagedKeyPkcs11BindingModel.objects.create(
        managed_key=managed_key,
        provider_profile=profile,
        key_id_hex='aabbccdd',
    )

    backend = _backend_with_adapter(adapter)

    backend.sign(
        key=managed_key.to_managed_key_ref(),
        data=b'secret payload bytes',
        request=SignRequest.rsa_pkcs1v15_sha256(),
    )

    entry = AuditLog.objects.get(operation_type=AuditLog.OperationType.CRYPTO_SIGN)
    assert entry.target == managed_key
    assert entry.target_display == 'Managed crypto key: signer/rsa'
    assert entry.details['status'] == 'success'
    assert entry.details['backend_kind'] == BackendKind.PKCS11
    assert entry.details['profile_name'] == 'provider-1'
    assert entry.details['key_algorithm'] == KeyAlgorithm.RSA
    assert entry.details['signature_algorithm'] == 'rsa-pkcs1v15'
    assert entry.details['hash_algorithm'] == 'sha256'
    assert entry.details['data_length'] == len(b'secret payload bytes')
    assert 'operation' not in entry.details
    assert 'data' not in entry.details
    assert 'payload' not in entry.details
    assert 'signature' not in entry.details
    assert 'auth_source_ref' not in entry.details
    assert 'module_path' not in entry.details


@pytest.mark.django_db
def test_crypto_backend_audit_does_not_persist_when_disabled() -> None:
    """Crypto backend debug tracing can run without persistent audit rows."""
    profile = _create_pkcs11_profile(name='provider-1', active=True)
    LoggingConfig.objects.update_or_create(
        id=1,
        defaults={'log_level': 'INFO', 'crypto_backend_audit_enabled': False},
    )

    public_key = rsa.generate_private_key(public_exponent=65537, key_size=2048).public_key()
    adapter = FakeAdapter(
        public_key=public_key,
        generated_binding=Pkcs11ManagedKeyBinding(
            key_id=b'\xaa\xbb\xcc\xdd',
            algorithm=KeyAlgorithm.RSA,
            signing_execution_mode=SigningExecutionMode.ALLOW_APPLICATION_HASH,
        ),
        signature=b'app-signature',
    )

    managed_key = CryptoManagedKeyModel.objects.create(
        alias='signer/rsa',
        provider_label='signer/rsa',
        provider_profile=profile,
        algorithm='rsa',
        public_key_fingerprint_sha256='b' * 64,
        signing_execution_mode=SigningExecutionMode.ALLOW_APPLICATION_HASH.value,
        policy_snapshot={'extractable': False, 'ephemeral': False, 'usages': ['sign', 'verify']},
    )
    CryptoManagedKeyPkcs11BindingModel.objects.create(
        managed_key=managed_key,
        provider_profile=profile,
        key_id_hex='aabbccdd',
    )

    backend = _backend_with_adapter(adapter)

    backend.sign(
        key=managed_key.to_managed_key_ref(),
        data=b'secret payload bytes',
        request=SignRequest.rsa_pkcs1v15_sha256(),
    )

    assert not AuditLog.objects.filter(operation_type=AuditLog.OperationType.CRYPTO_SIGN).exists()


@pytest.mark.django_db
def test_verify_managed_key_updates_repository_status() -> None:
    """Managed-key verification updates repository status from backend verification."""
    profile = _create_pkcs11_profile(name='provider-1', active=True)

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
        provider_label='verify/rsa',
        provider_profile=profile,
        algorithm='rsa',
        public_key_fingerprint_sha256='b' * 64,
        signing_execution_mode=SigningExecutionMode.COMPLETE_BACKEND.value,
        policy_snapshot={'extractable': False, 'ephemeral': False, 'usages': ['sign', 'verify']},
    )
    CryptoManagedKeyPkcs11BindingModel.objects.create(
        managed_key=managed_key,
        provider_profile=profile,
        key_id_hex='aabbccdd',
    )

    backend = _backend_with_adapter(adapter)

    verification = backend.verify_managed_key(managed_key.to_managed_key_ref())

    managed_key.refresh_from_db()
    assert verification.status is ManagedKeyVerificationStatus.MISMATCH
    assert verification.key.id == managed_key.id
    assert managed_key.status == ManagedKeyStatus.MISMATCH
    assert managed_key.last_verification_error == 'Managed key binding resolved to a different public key.'


@pytest.mark.django_db
def test_verify_managed_key_audits_runtime_failures() -> None:
    """Managed-key verification records non-domain provider failures before reraising."""
    profile = _create_pkcs11_profile(name='provider-1', active=True)
    LoggingConfig.objects.update_or_create(
        id=1,
        defaults={'log_level': 'INFO', 'crypto_backend_audit_enabled': True},
    )

    public_key = rsa.generate_private_key(public_exponent=65537, key_size=2048).public_key()
    adapter = FakeAdapter(
        public_key=public_key,
        generated_binding=Pkcs11ManagedKeyBinding(
            key_id=b'\xaa\xbb\xcc\xdd',
            algorithm=KeyAlgorithm.RSA,
        ),
        verification_exception=RuntimeError('provider crashed'),
    )

    managed_key = CryptoManagedKeyModel.objects.create(
        alias='verify/runtime-error',
        provider_label='verify/runtime-error',
        provider_profile=profile,
        algorithm='rsa',
        public_key_fingerprint_sha256='b' * 64,
        signing_execution_mode=SigningExecutionMode.COMPLETE_BACKEND.value,
        policy_snapshot={'extractable': False, 'ephemeral': False, 'usages': ['sign', 'verify']},
    )
    CryptoManagedKeyPkcs11BindingModel.objects.create(
        managed_key=managed_key,
        provider_profile=profile,
        key_id_hex='aabbccdd',
    )

    backend = _backend_with_adapter(adapter)

    with pytest.raises(RuntimeError, match='provider crashed'):
        backend.verify_managed_key(managed_key.to_managed_key_ref())

    managed_key.refresh_from_db()
    assert managed_key.status == ManagedKeyStatus.ERROR
    assert managed_key.last_verification_error == 'provider crashed'

    entry = AuditLog.objects.get(operation_type=AuditLog.OperationType.CRYPTO_VERIFY_MANAGED_KEY)
    assert entry.target == managed_key
    assert entry.details['status'] == 'error'
    assert entry.details['error_type'] == 'RuntimeError'
