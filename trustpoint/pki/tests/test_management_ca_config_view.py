# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Tests for the certificate-authentication management CA selection page."""

from __future__ import annotations

from datetime import timedelta
from importlib import import_module
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from django.contrib.auth import get_user_model
from django.apps import apps
from django.core.exceptions import ValidationError
from django.db import connection
from django.test import Client
from django.urls import reverse

from management.models import CertificateAuthenticationConfig
from pki.services.user_client_certificate import create_user_client_certificate
from pki.models import CaModel, CertificateProfileModel
from pki.tests.managed_ca_helpers import create_managed_root_ca
from pki.util.x509 import CertificateGenerator
from users.models import UserClientCertificate
from users.authentication import ClientCertificateBackend

pytestmark = pytest.mark.django_db


@pytest.fixture
def superuser_client() -> Client:
    """Return a logged-in superuser."""
    user = get_user_model().objects.create_superuser(
        username='ca-config-admin',
        password='test-password',  # noqa: S106
    )
    client = Client()
    client.force_login(user)
    return client


def _management_ca(name: str) -> CaModel:
    cert, key = create_managed_root_ca(name)
    return CertificateGenerator.save_issuing_ca(
        issuing_ca_cert=cert,
        private_key=key,
        chain=[],
        unique_name=name,
        ca_role=CaModel.CaRole.MANAGEMENT,
    )


def test_page_has_no_lifecycle_actions_for_management_ca(superuser_client: Client) -> None:
    """Generating, replacing, and deleting CAs is no longer offered on the page."""
    response = superuser_client.get(reverse('management:certificate_authentication'))

    assert response.status_code == 200  # noqa: PLR2004
    assert b'No management CA is selected.' in response.content
    assert b'Generate management CA' not in response.content
    assert b'Replace management CA' not in response.content
    assert b'Delete management CA' not in response.content


def test_page_shows_and_saves_the_selected_management_ca(superuser_client: Client) -> None:
    """The explicit selection form stores the chosen management CA."""
    ca = _management_ca('Management Config CA')

    response = superuser_client.post(
        reverse('management:certificate_authentication'),
        {'selected_ca_id': ca.pk},
    )

    assert response.status_code == 302  # noqa: PLR2004
    assert CertificateAuthenticationConfig.objects.filter(issuing_ca=ca).exists()
    config = CertificateAuthenticationConfig.objects.get(issuing_ca=ca)
    assert config.certificate_profile.unique_name == 'user_client'

    response = superuser_client.get(reverse('management:certificate_authentication'))
    assert ca.unique_name.encode() in response.content
    assert b'Save Configuration' in response.content


def test_new_authentication_config_uses_stored_default_profile() -> None:
    """Configuration creation selects the installed user certificate profile automatically."""
    ca = _management_ca('Default User Profile CA')
    config = CertificateAuthenticationConfig.objects.create(issuing_ca=ca)
    assert config.certificate_profile.unique_name == 'user_client'


def test_default_profile_migration_preserves_explicit_selection() -> None:
    """Backfill unset profiles without replacing custom policies or selected defaults."""
    default = CertificateProfileModel.objects.get(unique_name='user_client')
    customized = default.profile
    customized['validity']['days'] = 17
    default.profile_json = customized
    default.save()
    unconfigured = CertificateAuthenticationConfig.objects.create(
        issuing_ca=_management_ca('Unconfigured User CA'),
        certificate_profile=None,
    )
    explicit = CertificateAuthenticationConfig.objects.create(
        issuing_ca=_management_ca('Explicit User CA'),
        certificate_profile=_user_profile(),
    )

    migration = import_module('management.migrations.0008_default_user_certificate_profile')
    migration.install_default_user_profile(apps, SimpleNamespace(connection=connection))

    unconfigured.refresh_from_db()
    explicit.refresh_from_db()
    default.refresh_from_db()
    assert unconfigured.certificate_profile == default
    assert explicit.certificate_profile.unique_name == 'custom_user_client'
    assert default.profile == customized


def _user_profile(*, validity_days: int = 2, **extensions) -> CertificateProfileModel:
    return CertificateProfileModel.objects.create(
        unique_name='custom_user_client',
        display_name='User Client',
        profile_json={
            'type': 'cert_profile',
            'subj': {
                'cn': {'default': 'Configured User Client'},
                'organization_name': {'default': 'Example Corp'},
                'country_name': {'default': '{{ domain.country }}'},
                'serial_number': {'value': 'wrong-user'},
            },
            'ext': {
                'basic_constraints': {'ca': False},
                'key_usage': {'digital_signature': True},
                'extended_key_usage': {'usages': ['client_auth']},
                'subject_alternative_name': {'rfc822_names': ['client@example.test']},
                **extensions,
            },
            'validity': {'days': validity_days},
        },
    )


@pytest.mark.parametrize('validity_days', [2, 9999])
@pytest.mark.parametrize('client_auth', ['client_auth', 'clientAuth', '1.3.6.1.5.5.7.3.2'])
def test_selected_profile_controls_issued_user_certificate(
    superuser_client: Client,
    validity_days: int,
    client_auth: str,
) -> None:
    """The saved selection reaches issuance, while identity and CA validity remain enforced."""
    ca = _management_ca('User Profile CA')
    profile = _user_profile(validity_days=validity_days, extended_key_usage={'usages': [client_auth]})
    user = get_user_model().objects.get(username='ca-config-admin')
    response = superuser_client.post(
        reverse('management:certificate_authentication'),
        {'selected_ca_id': ca.pk, 'certificate_profile': profile.pk},
    )
    assert response.status_code == 302
    assert CertificateAuthenticationConfig.objects.get(issuing_ca=ca).certificate_profile == profile
    response = superuser_client.get(reverse('management:certificate_authentication'))
    assert response.context['form']['certificate_profile'].value() == profile.pk

    CertificateAuthenticationConfig.objects.filter(issuing_ca=ca).update(enabled=True)
    response = superuser_client.post(reverse('users:profile_certificate_authentication'), {'identifier': 'laptop'})
    assert response.status_code == 200
    key, certificate, _chain = pkcs12.load_key_and_certificates(b''.join(response.streaming_content), None)
    assert key is not None
    assert certificate is not None
    ClientCertificateBackend._validate_issuer(certificate)
    assert isinstance(key, rsa.RSAPrivateKey)
    assert key.key_size == ca.get_certificate().public_key().key_size
    assert certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == 'Configured User Client'
    assert certificate.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)[0].value == 'Example Corp'
    assert not certificate.subject.get_attributes_for_oid(NameOID.COUNTRY_NAME)
    assert certificate.subject.get_attributes_for_oid(NameOID.USER_ID)[0].value == user.username
    assert certificate.subject.get_attributes_for_oid(NameOID.SERIAL_NUMBER)[0].value == str(user.pk)
    assert certificate.subject.get_attributes_for_oid(NameOID.UNSTRUCTURED_NAME)[0].value == 'laptop'
    if validity_days == 2:
        assert certificate.not_valid_after_utc - certificate.not_valid_before_utc == timedelta(days=2, minutes=5)
    else:
        assert certificate.not_valid_after_utc == ca.get_certificate().not_valid_after_utc
    assert certificate.not_valid_after_utc <= ca.get_certificate().not_valid_after_utc
    assert (
        ExtendedKeyUsageOID.CLIENT_AUTH in certificate.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    )
    assert certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(
        x509.RFC822Name,
    ) == ['client@example.test']


@pytest.mark.parametrize(
    'extensions',
    [
        {'basic_constraints': {'ca': True}},
        {'key_usage': {'digital_signature': False}},
        {'key_usage': {'digital_signature': True, 'key_cert_sign': True}},
        {'key_usage': {'digital_signature': True, 'crl_sign': True}},
        {'extended_key_usage': {'usages': ['server_auth']}},
        {'subject_alternative_name': {'critical': True, 'rfc822_names': ['client@example.test']}},
    ],
)
def test_unsuitable_profile_does_not_change_saved_configuration(superuser_client: Client, extensions: dict) -> None:
    """Reject unsuitable defaults and roll back CA selection alongside the profile change."""
    old_ca = _management_ca('Old User CA')
    CertificateAuthenticationConfig.objects.create(issuing_ca=old_ca, enabled=True)
    new_ca = _management_ca('New User CA')
    profile = _user_profile(**extensions)

    response = superuser_client.post(
        reverse('management:certificate_authentication'),
        {'selected_ca_id': new_ca.pk, 'certificate_profile': profile.pk},
    )

    assert response.status_code == 200
    assert response.context['form'].errors
    assert CertificateAuthenticationConfig.objects.get(issuing_ca=old_ca).enabled
    assert not CertificateAuthenticationConfig.objects.filter(issuing_ca=new_ca).exists()


@pytest.mark.parametrize(
    ('extensions', 'message'),
    [
        ({'key_usage': {'digital_signature': False}}, 'end-entity profile'),
        ({'subject_alternative_name': {'critical': True, 'rfc822_names': ['client@example.test']}}, 'noncritical'),
    ],
)
def test_profile_is_revalidated_at_issuance(superuser_client: Client, extensions: dict, message: str) -> None:
    """Editing a selected profile cannot bypass TLS client usage restrictions."""
    ca = _management_ca('Changed Profile CA')
    profile = _user_profile(**extensions)
    CertificateAuthenticationConfig.objects.create(issuing_ca=ca, certificate_profile=profile)
    user = get_user_model().objects.get(username='ca-config-admin')

    with pytest.raises(ValidationError, match=message):
        create_user_client_certificate(user.pk, 'laptop')


@pytest.mark.parametrize('policy_key', ['default', 'value'])
def test_required_empty_placeholder_is_rejected_at_selection_and_issuance(
    superuser_client: Client,
    policy_key: str,
) -> None:
    """An unavailable required attribute must not disappear after profile validation."""
    ca = _management_ca('Required Country CA')
    profile = _user_profile()
    definition = profile.profile
    definition['subj']['country_name'] = {'required': True, policy_key: '{{ domain.country }}'}
    profile.profile_json = definition
    profile.save()

    response = superuser_client.post(
        reverse('management:certificate_authentication'),
        {'selected_ca_id': ca.pk, 'certificate_profile': profile.pk},
    )

    assert response.status_code == 200
    assert 'country_name' in str(response.context['form'].errors)
    assert not CertificateAuthenticationConfig.objects.filter(issuing_ca=ca).exists()
    CertificateAuthenticationConfig.objects.create(issuing_ca=ca, certificate_profile=profile)
    user = get_user_model().objects.get(username='ca-config-admin')
    with pytest.raises(ValidationError, match='country_name.*required'):
        create_user_client_certificate(user.pk, 'missing-country')


def test_unsupported_pkcs12_download_returns_form_error(superuser_client: Client) -> None:
    """Unsupported export algorithms fail before saving a certificate the user cannot download."""
    ca = _management_ca('Unsupported Export CA')
    CertificateAuthenticationConfig.objects.create(issuing_ca=ca, enabled=True)
    message = 'PKCS#12 serialization is not supported for ML-DSA private keys.'

    with patch('users.views.CredentialSerializer.as_pkcs12', side_effect=TypeError(message)):
        response = superuser_client.post(
            reverse('users:profile_certificate_authentication'),
            {'identifier': 'unsupported-key'},
        )

    assert response.status_code == 200
    assert message in response.context['form'].non_field_errors()
    assert not UserClientCertificate.objects.filter(identifier='unsupported-key').exists()
