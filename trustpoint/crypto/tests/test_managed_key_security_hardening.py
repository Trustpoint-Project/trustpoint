# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Regression tests for managed-key security hardening."""

from __future__ import annotations

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from crypto.application.service import TrustpointCryptoBackend
from crypto.domain.errors import ProviderConfigurationError
from crypto.domain.policies import KeyPolicy
from crypto.domain.specs import SignRequest
from crypto.models import (
    BackendKind,
    CryptoManagedKeyModel,
    CryptoManagedKeyPkcs11BindingModel,
    CryptoProviderProfileModel,
    ManagedKeyStatus,
)
from management.models import SecurityConfig

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
