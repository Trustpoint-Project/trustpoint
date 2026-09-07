# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Tests for owner-credential API helper behavior."""

from __future__ import annotations

import pytest

from pki.models.cert_profile import CertificateProfileModel
from pki.views.owner_credentials_api import (
    _build_request_data,
    _public_key_info_from_key_type,
    _resolve_cert_profile,
)


def test_build_request_data_normalizes_subject_sans_and_validity() -> None:
    """Flat API fields become the nested profile-request representation."""
    result = _build_request_data({
        'common_name': 'device.example',
        'organization_name': '',
        'dns_names': 'device.example, api.example',
        'ip_addresses': [' 192.0.2.1 ', ''],
        'uris': ['urn:device'],
        'days': 30,
        'hours': None,
        'minutes': '5',
        'seconds': 0,
    })

    assert result == {
        'subj': {'common_name': 'device.example'},
        'ext': {'subject_alternative_name': {
            'dns_names': ['device.example', 'api.example'],
            'ip_addresses': ['192.0.2.1'],
            'uris': ['urn:device'],
        }},
        'validity': {'days': 30, 'minutes': 5, 'seconds': 0},
    }


def test_build_request_data_ignores_empty_optional_values() -> None:
    """Empty subjects, SANs, and absent validity values are omitted."""
    assert _build_request_data({}) == {
        'subj': {},
        'ext': {'subject_alternative_name': {}},
        'validity': {},
    }


@pytest.mark.parametrize(
    ('key_type', 'algorithm', 'size'),
    [('RSA-2048', 'RSA', 2048), ('RSA-4096', 'RSA', 4096), ('ECC-SECP256R1', 'ECC', 256)],
)
def test_public_key_info_parses_supported_key_types(key_type: str, algorithm: str, size: int) -> None:
    """Supported RSA and EC key type strings map to public-key metadata."""
    info = _public_key_info_from_key_type(key_type)

    assert info.public_key_algorithm_oid.name == algorithm
    assert info.key_size == size


def test_public_key_info_rejects_unknown_curve() -> None:
    """Unknown curve names are rejected instead of silently defaulting."""
    with pytest.raises(KeyError):
        _public_key_info_from_key_type('ECC-unknown')


@pytest.mark.django_db
def test_resolve_cert_profile_prefers_explicit_pk_then_default_then_first() -> None:
    """Profile lookup honors explicit, named-default, and deterministic fallback order."""
    first = CertificateProfileModel.objects.create(
        unique_name='a-profile', display_name='A', profile_json={'type': 'cert_profile'}
    )
    named = CertificateProfileModel.objects.create(
        unique_name='preferred', display_name='Z', profile_json={'type': 'cert_profile'}
    )

    assert _resolve_cert_profile(named.pk, 'missing') == named
    assert _resolve_cert_profile(None, 'preferred') == named
    assert _resolve_cert_profile(None, 'missing') == first


@pytest.mark.django_db
def test_resolve_cert_profile_raises_when_no_profiles_exist() -> None:
    """Profile resolution reports the missing-profile condition."""
    with pytest.raises(CertificateProfileModel.DoesNotExist):
        _resolve_cert_profile(None, 'missing')
