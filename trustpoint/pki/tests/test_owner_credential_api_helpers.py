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


@pytest.mark.parametrize('onboarding', [False, True])
def test_est_context_selects_matching_credentials_and_truststore(onboarding):
    """Basic auth and mTLS must use their respective credentials and truststores."""
    from types import SimpleNamespace

    from pki.models import OwnerCredentialModel
    from pki.services.owner_credential import build_owner_credential_est_context_kwargs

    basic_truststore, mtls_truststore = object(), object()
    credential = SimpleNamespace(certificate=SimpleNamespace(cert_pem='client certificate'), private_key='client key')
    owner = SimpleNamespace(
        owner_credential_type=(
            OwnerCredentialModel.OwnerCredentialTypeChoice.REMOTE_EST_ONBOARDING
            if onboarding else OwnerCredentialModel.OwnerCredentialTypeChoice.REMOTE_EST
        ),
        remote_host='est.example.test', remote_port=8443, remote_path='/simpleenroll', est_username='device',
        no_onboarding_config=SimpleNamespace(est_password='secret', trust_store=basic_truststore),
        onboarding_config=SimpleNamespace(trust_store=mtls_truststore),
        domain_credential=SimpleNamespace(credential=credential),
    )
    profile = CertificateProfileModel(unique_name='test-profile')
    result = build_owner_credential_est_context_kwargs(owner, profile)

    assert result['certificate_profile_model'] is profile
    assert result['est_server_host'] == 'est.example.test'
    assert result['est_server_port'] == 8443
    assert result['est_server_path'] == '/simpleenroll'
    if onboarding:
        assert result['est_server_truststore'] is mtls_truststore
        assert result['est_client_cert_pem'] == 'client certificate'
        assert result['est_client_key_pem'] == 'client key'
        assert 'est_password' not in result
    else:
        assert result['est_server_truststore'] is basic_truststore
        assert result['est_username'] == 'device'
        assert result['est_password'] == 'secret'
        assert 'est_client_key_pem' not in result


@pytest.mark.parametrize('ui', [False, True])
@pytest.mark.parametrize('missing_certificate', [False, True])
def test_est_context_keeps_ui_errors_translated_and_api_errors_plain(ui, missing_certificate, monkeypatch):
    """The shared builder retains each entry point's error presentation."""
    from types import SimpleNamespace

    from devices.views import owner_credentials
    from pki.models import OwnerCredentialModel
    from pki.views.owner_credentials_api import DevOwnerIdViewSet

    monkeypatch.setattr(owner_credentials, '_', lambda message: f'translated: {message}')
    owner = SimpleNamespace(
        owner_credential_type=OwnerCredentialModel.OwnerCredentialTypeChoice.REMOTE_EST_ONBOARDING,
        remote_host='est.example.test', remote_port=8443, remote_path='/simpleenroll',
        onboarding_config=None,
        domain_credential=(
            SimpleNamespace(credential=SimpleNamespace(certificate=None)) if missing_certificate else None
        ),
    )
    consumer = owner_credentials.OwnerCredentialRequestCertEstView() if ui else DevOwnerIdViewSet()
    with pytest.raises(ValueError) as error:
        consumer._build_est_context_kwargs(owner, CertificateProfileModel(unique_name='test-profile'))
    expected = (
        'The domain credential has no certificate. Please issue a domain credential first.' if missing_certificate
        else 'No domain credential found for this owner credential. Please issue a domain credential first.'
    )
    assert str(error.value) == (f'translated: {expected}' if ui else expected)
