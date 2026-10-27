# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Key-type catalog and conversions shared by forms, APIs and issuance services.

Catalog membership describes product choices, not backend availability or security
policy. Legacy signer and AutoGenPKI identifiers resolve to the same definitions
without changing submitted values or database fields.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from django.utils.translation import gettext_noop as _
from trustpoint_core.oid import NamedCurve, PublicKeyAlgorithmOid, PublicKeyInfo

from crypto.domain.algorithms import EllipticCurveName
from crypto.domain.specs import EcKeySpec, MlDsaKeySpec, MlDsaVariant, RsaKeySpec

if TYPE_CHECKING:
    from crypto.domain.specs import KeySpec


@dataclass(frozen=True, slots=True)
class KeyTypeDefinition:
    """One product key type with its backend specification and legacy identifiers."""

    value: str
    label: str
    key_spec: KeySpec
    autogen_value: str | None = None
    signer_choice: tuple[str, str] | None = None


KEY_TYPES = (
    KeyTypeDefinition('RSA-2048', _('RSA 2048'), RsaKeySpec(2048), 'RSA2048SHA256', ('rsa_2048', _('RSA 2048'))),
    KeyTypeDefinition('RSA-3072', _('RSA 3072'), RsaKeySpec(3072), signer_choice=('rsa_3072', _('RSA 3072'))),
    KeyTypeDefinition('RSA-4096', _('RSA 4096'), RsaKeySpec(4096), 'RSA4096SHA256', ('rsa_4096', _('RSA 4096'))),
    KeyTypeDefinition(
        'ECC-SECP256R1',
        _('ECC SECP256R1'),
        EcKeySpec(EllipticCurveName.SECP256R1),
        'SECP256R1SHA256',
        ('ec_secp256r1', _('EC SECP256R1')),
    ),
    KeyTypeDefinition(
        'ECC-SECP384R1',
        _('ECC SECP384R1'),
        EcKeySpec(EllipticCurveName.SECP384R1),
        signer_choice=('ec_secp384r1', _('EC SECP384R1')),
    ),
    KeyTypeDefinition('ECC-SECP521R1', _('ECC SECP521R1'), EcKeySpec(EllipticCurveName.SECP521R1)),
    KeyTypeDefinition('MLDSA-44', _('ML-DSA-44'), MlDsaKeySpec(MlDsaVariant.MLDSA44), 'MLDSA44'),
    KeyTypeDefinition('MLDSA-65', _('ML-DSA-65'), MlDsaKeySpec(MlDsaVariant.MLDSA65), 'MLDSA65'),
    KeyTypeDefinition('MLDSA-87', _('ML-DSA-87'), MlDsaKeySpec(MlDsaVariant.MLDSA87), 'MLDSA87'),
)

_KEY_TYPES_BY_VALUE = {
    value: definition
    for definition in KEY_TYPES
    for value in (
        definition.value,
        *((definition.autogen_value,) if definition.autogen_value else ()),
        *((definition.signer_choice[0],) if definition.signer_choice else ()),
    )
}
KEY_TYPE_CHOICES = [(definition.value, definition.label) for definition in KEY_TYPES]
OWNER_CREDENTIAL_KEY_TYPE_CHOICES = [
    (definition.value, definition.label)
    for definition in KEY_TYPES
    if isinstance(definition.key_spec, (RsaKeySpec, EcKeySpec))
]
TLS_KEY_TYPE_CHOICES = [
    (definition.value, definition.label)
    for definition in KEY_TYPES
    if isinstance(definition.key_spec, RsaKeySpec)
    or (isinstance(definition.key_spec, EcKeySpec) and definition.key_spec.curve != EllipticCurveName.SECP521R1)
]
SIGNER_KEY_TYPE_CHOICES = [definition.signer_choice for definition in KEY_TYPES if definition.signer_choice]


def _definition(key_type: str) -> KeyTypeDefinition:
    try:
        return _KEY_TYPES_BY_VALUE[key_type]
    except KeyError as exc:
        msg = f'Unsupported key type {key_type!r}.'
        raise ValueError(msg) from exc


def normalize_key_type(key_type: str) -> str:
    """Resolve a catalog value or an explicit legacy alias to the canonical value."""
    return _definition(key_type).value


def key_spec_for_key_type(key_type: str) -> KeySpec:
    """Resolve a key-type identifier to the immutable backend key specification."""
    return _definition(key_type).key_spec


def public_key_info_from_key_type(key_type: str) -> PublicKeyInfo:
    """Resolve the same catalog definition to Trustpoint Core public-key metadata."""
    spec = key_spec_for_key_type(key_type)
    if isinstance(spec, RsaKeySpec):
        return PublicKeyInfo(public_key_algorithm_oid=PublicKeyAlgorithmOid.RSA, key_size=spec.key_size)
    if isinstance(spec, EcKeySpec):
        return PublicKeyInfo(
            public_key_algorithm_oid=PublicKeyAlgorithmOid.ECC,
            named_curve=NamedCurve[spec.curve.name],
        )
    return PublicKeyInfo(public_key_algorithm_oid=PublicKeyAlgorithmOid[spec.variant.name.replace('MLDSA', 'ML_DSA_')])
