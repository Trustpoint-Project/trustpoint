"""Tests for explicitly exportable managed TLS deployment keys."""

from __future__ import annotations

from unittest.mock import patch

import pytest
from cryptography.hazmat.primitives import serialization

from crypto.adapters.software.backend import SoftwareBackend
from crypto.application.service import TrustpointCryptoBackend
from crypto.domain.errors import AuthenticationError, ProviderConfigurationError, ProviderOperationNotImplementedError
from crypto.domain.policies import KeyPolicy, SigningExecutionMode
from crypto.domain.specs import RsaKeySpec
from crypto.models import (
    BackendKind,
    CryptoManagedKeyModel,
    CryptoProviderProfileModel,
    CryptoProviderSoftwareConfigModel,
    SoftwareKeyEncryptionSource,
)
from pki.models.credential import CredentialModel

pytestmark = pytest.mark.django_db


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


@pytest.mark.usefixtures('export_profile')
def test_export_private_key_pkcs8_rejects_nonextractable_key() -> None:
    """The default CA policy stays non-exportable even on an export-enabled provider."""
    backend = TrustpointCryptoBackend()
    key = backend.generate_managed_key(
        alias='ca/root', key_spec=RsaKeySpec(key_size=2048), policy=KeyPolicy.managed_signing_key(),
    )
    with pytest.raises(ProviderConfigurationError, match='not extractable'):
        backend.export_private_key_pkcs8(key)


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
