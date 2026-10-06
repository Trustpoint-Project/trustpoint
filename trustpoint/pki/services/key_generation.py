# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Shared backend-aware key selection and pending credential creation."""

from __future__ import annotations

from typing import TYPE_CHECKING

from crypto.application.capabilities import get_active_backend_capability_report
from crypto.application.service import TrustpointCryptoBackend
from crypto.domain.algorithms import EllipticCurveName
from crypto.domain.policies import KeyPolicy, SigningExecutionMode
from crypto.domain.specs import EcKeySpec, KeySpec, MlDsaKeySpec, MlDsaVariant, RsaKeySpec
from crypto.models import CryptoManagedKeyModel
from pki.models.credential import CredentialModel

if TYPE_CHECKING:
    from collections.abc import Sequence

    from crypto.application.capabilities import BackendCapabilityReport

KEY_TYPE_CHOICES = [
    ('RSA-2048', 'RSA 2048'),
    ('RSA-3072', 'RSA 3072'),
    ('RSA-4096', 'RSA 4096'),
    ('ECC-SECP256R1', 'ECC SECP256R1'),
    ('ECC-SECP384R1', 'ECC SECP384R1'),
    ('ECC-SECP521R1', 'ECC SECP521R1'),
    ('MLDSA-44', 'ML-DSA-44'),
    ('MLDSA-65', 'ML-DSA-65'),
    ('MLDSA-87', 'ML-DSA-87'),
]


def key_spec_for_key_type(key_type: str) -> KeySpec:
    """Map a UI key type to the backend key specification."""
    if key_type.startswith('RSA-'):
        return RsaKeySpec(key_size=int(key_type.split('-')[1]))
    if key_type.startswith('MLDSA-'):
        return MlDsaKeySpec(variant=MlDsaVariant('mldsa' + key_type.split('-')[1]))
    return EcKeySpec(curve=EllipticCurveName(key_type.split('-')[1].lower()))


def supported_key_type_choices(
    choices: Sequence[tuple[str, str]] = KEY_TYPE_CHOICES,
    *,
    report: BackendCapabilityReport | None = None,
) -> list[tuple[str, str]]:
    """Filter UI key types using the active backend's capabilities."""
    capability_report = report if report is not None else get_active_backend_capability_report()
    return [
        (value, label) for value, label in choices
        if capability_report.supports_key_spec(key_spec_for_key_type(value))
    ]


def generate_pending_credential(
    *,
    alias: str,
    key_type: str,
    credential_type: CredentialModel.CredentialTypeChoice,
    policy: KeyPolicy | None = None,
    backend: TrustpointCryptoBackend | None = None,
) -> CredentialModel:
    """Generate one backend key and persist a certificate-less credential."""
    key_ref = (backend or TrustpointCryptoBackend()).generate_managed_key(
        alias=alias,
        key_spec=key_spec_for_key_type(key_type),
        policy=policy or KeyPolicy.managed_signing_key(
            signing_execution_mode=SigningExecutionMode.ALLOW_APPLICATION_HASH,
        ),
    )
    return CredentialModel.save_managed_private_key_credential(
        credential_type=credential_type,
        managed_key=CryptoManagedKeyModel.objects.get(pk=key_ref.id),
    )
