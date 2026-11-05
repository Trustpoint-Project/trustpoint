# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Regression tests for catalog conversions and each flow's offered key types."""

from unittest.mock import patch

import pytest
from trustpoint_core.oid import KeyPairGenerator, PublicKeyInfo

from crypto.application.capabilities import BackendCapabilityReport
from crypto.domain.algorithms import EllipticCurveName
from crypto.domain.specs import EcKeySpec, MlDsaKeySpec, RsaKeySpec
from management.forms import TlsExternalCsrKeyForm
from pki.auto_gen_pki import AutoGenPki
from pki.forms.issuing_cas import IssuingCaAddRequestMixin
from pki.forms.owner_credential import OwnerCredentialAddRequestEstNoOnboardingForm
from pki.key_types import (
    KEY_TYPES,
    KEY_TYPE_CHOICES,
    OWNER_CREDENTIAL_KEY_TYPE_CHOICES,
    SIGNER_KEY_TYPE_CHOICES,
    TLS_KEY_TYPE_CHOICES,
    key_spec_for_key_type,
    normalize_key_type,
    public_key_info_from_key_type,
)
from pki.serializer.owner_credential import OwnerCredentialEstBasicAuthSerializer, OwnerCredentialEstMtlsSerializer
from pki.services.key_generation import supported_key_type_choices
from pki.util.keys import AutoGenPkiKeyAlgorithm
from signer.forms import SignerGenerateForm


@pytest.mark.parametrize(
    'key_type',
    [
        'RSA-2048',
        'RSA-3072',
        'RSA-4096',
        'ECC-SECP256R1',
        'ECC-SECP384R1',
        'ECC-SECP521R1',
        'MLDSA-44',
        'MLDSA-65',
        'MLDSA-87',
    ],
)
def test_core_metadata_generates_the_requested_key(key_type):
    """Core metadata and backend specs describe the same real key for every catalog entry."""
    info = public_key_info_from_key_type(key_type)
    key = KeyPairGenerator.generate_key_pair_for_public_key_info(info)
    assert PublicKeyInfo.from_private_key(key) == info
    spec = key_spec_for_key_type(key_type)
    if isinstance(spec, RsaKeySpec):
        assert key_type == f'RSA-{key.key_size}'
        assert spec.key_size == key.key_size
    elif isinstance(spec, EcKeySpec):
        assert key_type == f'ECC-{key.curve.name.upper()}'
        assert spec.curve.value == key.curve.name
    else:
        assert isinstance(spec, MlDsaKeySpec)
        assert key_type == f'MLDSA-{info.public_key_algorithm_oid.name.rsplit("_", 1)[1]}'
        assert spec.variant.value == info.public_key_algorithm_oid.name.lower().replace('_', '')


@pytest.mark.parametrize(
    ('legacy', 'canonical'),
    [
        ('rsa_2048', 'RSA-2048'),
        ('rsa_3072', 'RSA-3072'),
        ('rsa_4096', 'RSA-4096'),
        ('ec_secp256r1', 'ECC-SECP256R1'),
        ('ec_secp384r1', 'ECC-SECP384R1'),
        ('RSA2048SHA256', 'RSA-2048'),
        ('RSA4096SHA256', 'RSA-4096'),
        ('SECP256R1SHA256', 'ECC-SECP256R1'),
        ('MLDSA44', 'MLDSA-44'),
        ('MLDSA65', 'MLDSA-65'),
        ('MLDSA87', 'MLDSA-87'),
    ],
)
def test_legacy_identifiers_resolve_to_canonical_specs(legacy, canonical):
    """Persisted AutoGenPKI values and submitted signer values remain compatible."""
    assert normalize_key_type(legacy) == canonical
    assert key_spec_for_key_type(legacy) == key_spec_for_key_type(canonical)
    assert public_key_info_from_key_type(legacy) == public_key_info_from_key_type(canonical)


@pytest.mark.parametrize('algorithm', list(AutoGenPkiKeyAlgorithm))
def test_legacy_autogen_metadata_and_normalization_agree(algorithm):
    """AutoGenPKI naming and key generation cannot select different algorithms."""
    canonical = AutoGenPki._normalize_key_type(algorithm)
    assert algorithm.to_public_key_info() == public_key_info_from_key_type(canonical)
    assert AutoGenPki._key_type_identifier(algorithm) == canonical.replace('-', '')


@pytest.mark.parametrize(
    'value',
    [
        '',
        'RSA-1024',
        'RSA-2048-extra',
        'OTHER-SECP256R1',
        'ECC-unknown',
        'ECC-secp256r1',
        'ec_secp521r1',
        'MLDSA-128',
        ' RSA-2048',
    ],
)
@pytest.mark.parametrize('convert', [normalize_key_type, key_spec_for_key_type, public_key_info_from_key_type])
def test_unknown_identifiers_fail_consistently(value, convert):
    """Unsupported values and prefix lookalikes never fall back to another algorithm."""
    with pytest.raises(ValueError, match='Unsupported key type'):
        convert(value)


def test_catalog_identifiers_are_unique():
    """Canonical and legacy identifiers cannot shadow another entry."""
    values = []
    for definition in KEY_TYPES:
        values.append(definition.value)
        if definition.autogen_value:
            values.append(definition.autogen_value)
        if definition.signer_choice:
            values.append(definition.signer_choice[0])
    assert len(values) == len(set(values))
    assert len(KEY_TYPE_CHOICES) == 9


def test_owner_form_and_api_preserve_their_classical_choices():
    """Sharing a larger catalog must not expose PQC or legacy aliases in owner enrollment."""
    expected = ['RSA-2048', 'RSA-3072', 'RSA-4096', 'ECC-SECP256R1', 'ECC-SECP384R1', 'ECC-SECP521R1']
    form = OwnerCredentialAddRequestEstNoOnboardingForm()
    assert [value for value, _ in form.fields['key_type'].choices] == expected
    assert [value for value, _ in OWNER_CREDENTIAL_KEY_TYPE_CHOICES] == expected
    for serializer_type in (OwnerCredentialEstBasicAuthSerializer, OwnerCredentialEstMtlsSerializer):
        assert list(serializer_type().fields['key_type'].choices) == expected


def test_tls_and_signer_preserve_their_allowed_subsets():
    """TLS and signer generation retain their existing values and omit P-521 and ML-DSA."""
    assert [value for value, _ in TLS_KEY_TYPE_CHOICES] == [
        'RSA-2048',
        'RSA-3072',
        'RSA-4096',
        'ECC-SECP256R1',
        'ECC-SECP384R1',
    ]
    assert [value for value, _ in SIGNER_KEY_TYPE_CHOICES] == [
        'rsa_2048',
        'rsa_3072',
        'rsa_4096',
        'ec_secp256r1',
        'ec_secp384r1',
    ]
    assert dict(SignerGenerateForm.KEY_TYPE_CHOICES)['ec_secp256r1'] == 'EC SECP256R1'
    with pytest.raises(ValueError, match='Unsupported signer key type'):
        SignerGenerateForm._key_spec_for_key_type('ECC-SECP256R1')


@pytest.mark.parametrize('available', [False, True])
def test_backend_filtering_agrees_across_flows(available):
    """The same capability report filters canonical CA/TLS values and legacy signer values."""
    report = BackendCapabilityReport(
        backend_kind=None,
        profile_name=None,
        available=available,
        rsa_key_sizes=(3072,),
        ec_curves=(EllipticCurveName.SECP384R1,),
        mldsa_variants=('mldsa65',),
    )
    ca_values = ['RSA-3072', 'ECC-SECP384R1', 'MLDSA-65'] if available else []
    tls_values = ['RSA-3072', 'ECC-SECP384R1'] if available else []
    signer_values = ['rsa_3072', 'ec_secp384r1'] if available else []
    assert [value for value, _ in supported_key_type_choices(report=report)] == ca_values
    with patch('pki.forms.issuing_cas.get_active_backend_capability_report', return_value=report):
        assert [value for value, _ in IssuingCaAddRequestMixin._supported_key_type_choices()] == ca_values
    with patch('pki.services.key_generation.get_active_backend_capability_report', return_value=report):
        form = TlsExternalCsrKeyForm()
        assert [value for value, _ in form.fields['key_type'].choices] == tls_values
        if available:
            assert form.fields['key_type'].initial == 'RSA-3072'
    with patch('signer.forms.get_active_backend_capability_report', return_value=report):
        form = SignerGenerateForm()
        assert [value for value, _ in form.fields['key_type'].choices] == signer_values
        for value in signer_values:
            assert report.supports_key_spec(form._key_spec_for_key_type(value))
