# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Tests for the protocol-specific default certificate profiles."""

from __future__ import annotations

from django.core.management import call_command

from pki.forms.cert_profiles import CertificateIssuanceForm
from pki.models import DomainModel
from pki.models.cert_profile import CertificateProfileModel
from pki.serializer.cert_profile import CertProfileSerializer
from pki.util.cert_profile import CertProfileModel as CertProfilePydanticModel

PROTOCOL_PROFILE_NAMES = {
    'bacnet_sc',
    'mqtt_server',
    'mqtt_client',
    'ipsec_ike',
    'eap_tls',
}


def test_protocol_profiles_load_validate_and_are_selectable(issuing_ca_instance: dict[str, object]) -> None:
    """The default loader makes protocol profiles available to domains and the API."""
    call_command('create_default_cert_profiles')

    profiles = {
        profile.unique_name: profile
        for profile in CertificateProfileModel.objects.filter(unique_name__in=PROTOCOL_PROFILE_NAMES)
    }

    assert profiles.keys() == PROTOCOL_PROFILE_NAMES
    for profile in profiles.values():
        CertProfilePydanticModel.model_validate(profile.profile)
        assert profile.is_default
        assert profile.credential_type == CertificateProfileModel.ProfileCredentialType.APPLICATION
        assert CertProfileSerializer(profile).data['unique_name'] == profile.unique_name

    domain = DomainModel.objects.create(
        unique_name='protocol-profile-domain',
        issuing_ca=issuing_ca_instance['issuing_ca'],
    )
    assert domain.get_allowed_cert_profile_names() >= PROTOCOL_PROFILE_NAMES


def test_mqtt_profiles_have_distinct_tls_roles() -> None:
    """MQTT server and client profiles carry their respective TLS EKUs."""
    call_command('create_default_cert_profiles')
    server = CertificateProfileModel.objects.get(unique_name='mqtt_server').profile
    client = CertificateProfileModel.objects.get(unique_name='mqtt_client').profile

    assert server['ext']['extended_key_usage']['usages'] == ['server_auth']
    assert client['ext']['extended_key_usage']['usages'] == ['client_auth']


def test_ipsec_profile_uses_ipsec_ike_extended_key_usage() -> None:
    """IKE authentication uses the dedicated IPsec IKE EKU rather than TLS EKUs."""
    call_command('create_default_cert_profiles')
    profile = CertificateProfileModel.objects.get(unique_name='ipsec_ike').profile

    assert profile['ext']['extended_key_usage']['usages'] == ['ipsec_ike']


def test_opc_ua_domain_profile_loads_with_required_uri(domain_instance: dict[str, object]) -> None:
    """The dedicated domain profile can be selected and requires a URI through the standard form."""
    call_command('create_default_cert_profiles')
    profile = CertificateProfileModel.objects.get(unique_name='opc_ua_domain_credential')
    assert profile.credential_type == CertificateProfileModel.ProfileCredentialType.DOMAIN
    CertProfilePydanticModel.model_validate(profile.profile)
    domain = domain_instance['domain']
    domain.domain_credential_profile = profile
    domain.save()
    assert domain.get_domain_credential_profile() == profile
    assert domain.get_allowed_cert_profile(profile.unique_name) == profile

    form = CertificateIssuanceForm(profile=profile.profile, domain=domain)
    assert form['common_name'].value() == 'Trustpoint Domain Credential'
    assert form.fields['uris'].required
    assert not form.fields['uris'].disabled
    assert form['days'].value() == profile.profile['validity']['days']
    form = CertificateIssuanceForm(profile=profile.profile, domain=domain, data={
        'common_name': 'Trustpoint Domain Credential',
    })
    assert not form.is_valid()
    assert 'uris' in form.errors
