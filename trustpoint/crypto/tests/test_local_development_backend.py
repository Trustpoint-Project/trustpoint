"""Tests for local sqlite development crypto defaults."""

from __future__ import annotations

from typing import Any

import pytest
from django.db import connection
from django.test.utils import CaptureQueriesContext

from appsecrets.models import AppSecretBackendKind, AppSecretBackendModel, AppSecretSoftwareConfigModel
from appsecrets.service import (
    CIPHERTEXT_PREFIX,
    AppSecretConfigurationError,
    clear_app_secret_cache,
    decrypt_app_secret,
    encrypt_app_secret,
)
from crypto.application.service import TrustpointCryptoBackend
from crypto.domain.policies import KeyPolicy
from crypto.domain.specs import RsaKeySpec, SignRequest
from crypto.models import (
    BackendKind,
    CryptoManagedKeyModel,
    CryptoManagedKeySoftwareBindingModel,
    CryptoProviderPkcs11ConfigModel,
    CryptoProviderProfileModel,
    CryptoProviderSoftwareConfigModel,
    Pkcs11AuthSource,
    SoftwareKeyEncryptionSource,
)

LOCAL_DEVELOPMENT_DEK_LENGTH_BYTES = 32


def _enable_local_dev_auto_config(settings: Any) -> None:
    """Enable the guarded local dev backend auto-configuration path."""
    settings.TRUSTPOINT_AUTO_CONFIGURE_LOCAL_SOFTWARE_BACKEND = True
    settings.TRUSTPOINT_IS_OPERATIONAL = True
    settings.TRUSTPOINT_IS_BOOTSTRAP = False
    settings.DEVELOPMENT_ENV = True
    settings.DOCKER_CONTAINER = False
    settings.TRUSTPOINT_OPERATIONAL_DATABASE = 'sqlite'


@pytest.mark.django_db
def test_local_dev_auto_configured_software_backend_supports_managed_crypto(settings: Any) -> None:
    """Local sqlite development can generate and use managed keys without an HSM."""
    _enable_local_dev_auto_config(settings)
    CryptoProviderProfileModel.objects.all().delete()

    backend = TrustpointCryptoBackend()
    key_ref = backend.generate_managed_key(
        alias='local-dev/root-ca',
        key_spec=RsaKeySpec(key_size=2048),
        policy=KeyPolicy.managed_signing_key(),
    )
    signature = backend.sign(
        key=key_ref,
        data=b'payload',
        request=SignRequest.rsa_pkcs1v15_sha256(),
    )

    profile = CryptoProviderProfileModel.objects.get(active=True)
    managed_key = CryptoManagedKeyModel.objects.get(pk=key_ref.id)
    software_config = CryptoProviderSoftwareConfigModel.objects.get(profile=profile)
    software_binding = CryptoManagedKeySoftwareBindingModel.objects.get(managed_key=managed_key)

    assert signature
    assert profile.backend_kind == BackendKind.SOFTWARE
    assert software_config.encryption_source == SoftwareKeyEncryptionSource.DEV_PLAINTEXT
    assert software_binding.encrypted_private_key_pkcs8_der


@pytest.mark.django_db
def test_local_dev_auto_configured_appsecret_backend_encrypts_fields(settings: Any) -> None:
    """Local sqlite development can encrypt app-secret values without prior wizard state."""
    _enable_local_dev_auto_config(settings)
    AppSecretSoftwareConfigModel.objects.all().delete()
    AppSecretBackendModel.objects.all().delete()
    clear_app_secret_cache()

    ciphertext = encrypt_app_secret('local secret')
    plaintext = decrypt_app_secret(ciphertext)

    backend = AppSecretBackendModel.objects.get()
    software_config = AppSecretSoftwareConfigModel.objects.get(backend=backend)

    assert ciphertext.startswith(CIPHERTEXT_PREFIX)
    assert plaintext == 'local secret'
    assert backend.backend_kind == AppSecretBackendKind.SOFTWARE
    assert len(bytes(software_config.raw_dek)) == LOCAL_DEVELOPMENT_DEK_LENGTH_BYTES


@pytest.mark.django_db
def test_local_dev_appsecret_decrypt_does_not_write_after_backend_is_ready(settings: Any) -> None:
    """Decrypting dashboard data should not perform local auto-config cleanup writes."""
    _enable_local_dev_auto_config(settings)
    AppSecretSoftwareConfigModel.objects.all().delete()
    AppSecretBackendModel.objects.all().delete()
    clear_app_secret_cache()
    ciphertext = encrypt_app_secret('local secret')
    clear_app_secret_cache()

    with CaptureQueriesContext(connection) as captured_queries:
        plaintext = decrypt_app_secret(ciphertext)

    write_sql_prefixes = ('INSERT ', 'UPDATE ', 'DELETE ')
    write_queries = [
        query['sql']
        for query in captured_queries.captured_queries
        if query['sql'].lstrip().upper().startswith(write_sql_prefixes)
    ]

    assert plaintext == 'local secret'
    assert write_queries == []


@pytest.mark.django_db
def test_local_dev_auto_config_does_not_mix_software_with_existing_pkcs11(settings: Any) -> None:
    """Local auto-config leaves explicit non-software backend state alone."""
    _enable_local_dev_auto_config(settings)
    AppSecretSoftwareConfigModel.objects.all().delete()
    AppSecretBackendModel.objects.all().delete()
    CryptoProviderProfileModel.objects.all().delete()
    clear_app_secret_cache()

    profile = CryptoProviderProfileModel.objects.create(
        name='explicit-pkcs11',
        backend_kind=BackendKind.PKCS11,
        active=False,
    )
    CryptoProviderPkcs11ConfigModel.objects.create(
        profile=profile,
        module_path='/usr/lib/test-pkcs11.so',
        token_label=None,
        token_serial=None,
        slot_id=1,
        auth_source=Pkcs11AuthSource.FILE,
        auth_source_ref='/var/lib/trustpoint/user-pin.txt',
    )

    with pytest.raises(AppSecretConfigurationError):
        encrypt_app_secret('local secret')

    assert not CryptoProviderProfileModel.objects.filter(backend_kind=BackendKind.SOFTWARE).exists()
    assert not AppSecretBackendModel.objects.exists()
