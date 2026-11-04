# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Regression tests for managed-key security hardening."""

from __future__ import annotations

from unittest.mock import Mock, patch

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from django.db.models.deletion import ProtectedError

from crypto.application.service import TrustpointCryptoBackend
from crypto.domain.errors import ProviderConfigurationError, ProviderUnavailableError
from crypto.domain.policies import KeyPolicy
from crypto.domain.specs import SignRequest
from crypto.models import (
    BackendKind,
    CryptoManagedKeyModel,
    CryptoManagedKeyPkcs11BindingModel,
    CryptoProviderProfileModel,
    ManagedKeyStatus,
)
from management.models import AuditLog, LoggingConfig, SecurityConfig
from pki.models import CredentialModel

pytestmark = pytest.mark.django_db


def _managed_key(*, status: str, backend_kind: str = BackendKind.PKCS11) -> CryptoManagedKeyModel:
    """Create a managed key in the requested verification state."""
    profile = CryptoProviderProfileModel.objects.create(
        name=f'provider-{status}',
        backend_kind=backend_kind,
        active=True,
    )
    managed_key = CryptoManagedKeyModel.objects.create(
        alias=f'key/{status}',
        provider_label=f'key/{status}',
        provider_profile=profile,
        algorithm='rsa',
        public_key_fingerprint_sha256='a' * 64,
        policy_snapshot={'extractable': True, 'ephemeral': False, 'usages': ['sign']},
        status=status,
    )
    if backend_kind == BackendKind.PKCS11:
        CryptoManagedKeyPkcs11BindingModel.objects.create(
            managed_key=managed_key,
            provider_profile=profile,
            key_id_hex='01020304',
        )
    return managed_key


@pytest.mark.parametrize(
    'status',
    [ManagedKeyStatus.MISSING, ManagedKeyStatus.MISMATCH, ManagedKeyStatus.ERROR],
)
def test_sign_rejects_unverified_managed_key(status: str) -> None:
    """Signing fails closed for any non-active managed-key state."""
    managed_key = _managed_key(status=status)

    with pytest.raises(ProviderConfigurationError, match='cannot be used for signing'):
        TrustpointCryptoBackend().sign(
            key=managed_key.to_managed_key_ref(),
            data=b'payload',
            request=SignRequest.rsa_pkcs1v15_sha256(),
        )


def test_private_key_import_rejects_ambiguous_security_policy() -> None:
    """Private-key import cannot choose an arbitrary SecurityConfig row."""
    CryptoProviderProfileModel.objects.create(
        name='software-provider',
        backend_kind=BackendKind.SOFTWARE,
        active=True,
    )
    SecurityConfig.objects.create(
        security_mode=SecurityConfig.SecurityModeChoices.LAB,
        allow_imported_private_keys=True,
    )
    SecurityConfig.objects.create(
        security_mode=SecurityConfig.SecurityModeChoices.BROWNFIELD,
        allow_imported_private_keys=True,
    )
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    with pytest.raises(ProviderConfigurationError, match='multiple SecurityConfig'):
        TrustpointCryptoBackend().import_managed_private_key(
            alias='imported/test',
            private_key=private_key,
            policy=KeyPolicy.managed_signing_key(),
        )


def test_destroy_referenced_key_never_touches_provider() -> None:
    """Protected credential references must be checked before irreversible destruction."""
    managed_key = _managed_key(status=ManagedKeyStatus.ACTIVE)
    CredentialModel.objects.create(
        credential_type=CredentialModel.CredentialTypeChoice.SIGNER,
        managed_private_key=managed_key,
    )
    LoggingConfig.objects.update_or_create(pk=1, defaults={'crypto_backend_audit_enabled': True})
    backend = TrustpointCryptoBackend()
    with patch.object(backend, '_build_adapter') as build_adapter, pytest.raises(ProtectedError):
        backend.destroy_managed_key(managed_key.to_managed_key_ref())

    build_adapter.assert_not_called()
    assert CryptoManagedKeyModel.objects.filter(pk=managed_key.pk).exists()
    assert CryptoManagedKeyPkcs11BindingModel.objects.filter(managed_key=managed_key).exists()
    entry = AuditLog.objects.get(operation_type=AuditLog.OperationType.CRYPTO_DESTROY_MANAGED_KEY)
    assert entry.details['status'] == 'error'


@pytest.mark.parametrize('provider_fails', [False, True])
def test_destroy_key_rolls_back_provider_failure_and_audits_result(provider_fails) -> None:
    """Provider failures restore the binding; success preserves the deleted key's audit identity."""
    managed_key = _managed_key(status=ManagedKeyStatus.ACTIVE)
    key_ref = managed_key.to_managed_key_ref()
    LoggingConfig.objects.update_or_create(pk=1, defaults={'crypto_backend_audit_enabled': True})

    def destroy_binding(binding):
        assert not CryptoManagedKeyModel.objects.filter(pk=key_ref.id).exists()
        if provider_fails:
            raise ProviderUnavailableError('provider unavailable')

    adapter = Mock()
    adapter.destroy_managed_key.side_effect = destroy_binding
    backend = TrustpointCryptoBackend()
    with patch.object(backend, '_build_adapter', return_value=adapter):
        if provider_fails:
            with pytest.raises(ProviderUnavailableError, match='provider unavailable'):
                backend.destroy_managed_key(key_ref)
        else:
            backend.destroy_managed_key(key_ref)

    adapter.destroy_managed_key.assert_called_once()
    adapter.close.assert_called_once()
    assert CryptoManagedKeyModel.objects.filter(pk=key_ref.id).exists() is provider_fails
    assert CryptoManagedKeyPkcs11BindingModel.objects.filter(managed_key_id=key_ref.id).exists() is provider_fails
    entry = AuditLog.objects.get(operation_type=AuditLog.OperationType.CRYPTO_DESTROY_MANAGED_KEY)
    assert entry.target_object_id == str(key_ref.id)
    assert entry.details['status'] == ('error' if provider_fails else 'success')
