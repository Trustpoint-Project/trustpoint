# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Behavioral coverage for CA/CRL management endpoints and their authorization."""

from datetime import timedelta
from unittest.mock import patch

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from django.contrib.auth.models import Permission
from django.core.files.uploadedfile import SimpleUploadedFile
from django.utils import timezone
from rest_framework.test import APIClient

from management.models import SecurityConfig
from management.models.audit_log import AuditLog
from pki.models import CaModel, CertificateModel, CrlModel
from pki.util.x509 import CertificateGenerator
from pki.models.ca_rollover import CaRolloverModel, CaRolloverState, CaRolloverStrategyType
from users.models import TrustpointUser


@pytest.fixture
def api():
    """Use an authenticated CA administrator without browser authentication middleware."""
    user = TrustpointUser.objects.create_superuser(username='ca-api-admin', password='test-password-123')
    user.role.permissions.add(Permission.objects.get(codename='manage_cas'))
    client = APIClient()
    client.force_authenticate(user)
    return client


@pytest.fixture
def ca(issuing_ca_instance):
    """Use the real managed-key CA fixture."""
    return issuing_ca_instance['issuing_ca']


def crl_upload(fixture, number=10, encoding=serialization.Encoding.PEM, signing_key=None):
    """Sign a CRL using the fixture CA, or another key for negative tests."""
    now = timezone.now()
    crl = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(fixture['cert'].subject)
        .last_update(now)
        .next_update(now + timedelta(days=1))
        .add_extension(x509.CRLNumber(number), critical=False)
        .sign(signing_key or fixture['priv_key'], hashes.SHA256())
    )
    return SimpleUploadedFile('test.crl', crl.public_bytes(encoding))


@pytest.mark.parametrize('url', ['/api/cas/', '/api/crls/', '/api/ca-rollovers/', '/api/issuing-cas/'])
def test_requires_ca_permission(url):
    """Anonymous and ordinary authenticated users cannot administer CAs or CRLs."""
    client = APIClient()
    assert client.get(url).status_code in (401, 403)
    user = TrustpointUser.objects.create_user(username='ordinary', password='test-password-123')
    client.force_authenticate(user)
    assert client.get(url).status_code == 403


def test_ca_inventory_includes_keyless_and_root(api, ca):
    """The full inventory exposes CA types omitted from the issuing inventory."""
    keyless = CaModel.objects.create(
        unique_name='keyless', ca_type=CaModel.CaTypeChoice.KEYLESS, certificate=ca.ca_certificate_model
    )
    response = api.get('/api/cas/')
    assert response.status_code == 200
    rows = response.data.get('results', []) if isinstance(response.data, dict) else response.data
    assert {row['id'] for row in rows} >= {ca.pk, keyless.pk}
    assert api.get(f'/api/cas/{keyless.pk}/').status_code == 200
    assert api.get(f'/api/issuing-cas/{keyless.pk}/').status_code == 404


def test_issuing_ca_retrieve_accepts_router_pk(api, ca):
    """Detail lookup must not fail because the legacy retrieve signature omitted pk."""
    response = api.get(f'/api/issuing-cas/{ca.pk}/')
    assert response.status_code == 200
    assert response.data['crl_validity_hours'] == 24
    assert 'private_key' not in response.data


@pytest.mark.parametrize('encoding', ['pem', 'der'])
def test_ca_certificate_download(api, ca, encoding):
    """CA downloads contain the same certificate in each supported encoding."""
    response = api.get(f'/api/cas/{ca.pk}/certificate/?encoding={encoding}')
    assert response.status_code == 200
    parser = x509.load_pem_x509_certificate if encoding == 'pem' else x509.load_der_x509_certificate
    assert parser(response.content).serial_number == ca.get_certificate().serial_number


def test_download_invalid_encoding_and_missing_certificate(api, ca):
    """Invalid encodings and pending certificates have explicit client errors."""
    ca.credential.certificate = None
    ca.credential.save()
    assert api.get(f'/api/cas/{ca.pk}/certificate/').status_code == 404
    assert api.get('/api/crls/999999/download/').status_code == 404


def test_ca_delete_protected_child(api, ca):
    """Deletion must preserve hierarchy guards and return validation instead of a 500."""
    CaModel.objects.create(
        unique_name='child', parent_ca=ca, ca_type=CaModel.CaTypeChoice.KEYLESS, certificate=ca.ca_certificate_model
    )
    response = api.delete(f'/api/cas/{ca.pk}/')
    assert response.status_code == 400
    assert CaModel.objects.filter(pk=ca.pk).exists()


def test_delete_unused_ca(api):
    """An unused CA can be deleted through the inventory endpoint."""
    cert, _ = CertificateGenerator.create_root_ca(cn='Unused')
    ca = CaModel.create_keyless_ca(unique_name='unused', certificate_obj=cert)
    pk = ca.pk
    assert api.delete(f'/api/cas/{pk}/').status_code == 204
    assert not CaModel.objects.filter(pk=pk).exists()


def test_crl_settings_partial_update_and_validation(api, ca):
    """PATCH preserves omitted values and enforces schedule/validity limits."""
    config = SecurityConfig(security_mode=SecurityConfig.SecurityModeChoices.LAB)
    config.apply_security_settings(save=False)
    config.save()
    url = f'/api/issuing-cas/{ca.pk}/crl-settings/'
    response = api.patch(url, {'crl_validity_hours': 12.5}, format='json')
    assert response.status_code == 200, response.data
    ca.refresh_from_db()
    assert ca.crl_validity_hours == 12.5
    assert ca.crl_cycle_interval_hours == 24
    assert api.patch(url, {'crl_cycle_interval_hours': 0.01}, format='json').status_code == 400
    ca.is_active = False
    ca.save()
    assert api.patch(url, {'crl_validity_hours': 5}, format='json').status_code == 400


def test_generate_crl_preserves_fractional_validity(api, ca):
    """CRL validity is measured in fractional hours, not truncated integers."""
    ca.crl_validity_hours = 1.5
    ca.save()
    response = api.post(f'/api/issuing-cas/{ca.pk}/generate-crl/')
    assert response.status_code == 200, response.data
    crl = ca.get_active_crl().get_crl_as_crypto()
    assert (crl.next_update_utc - crl.last_update_utc).total_seconds() == 5400


@pytest.mark.parametrize('encoding', [serialization.Encoding.PEM, serialization.Encoding.DER])
def test_crl_import_download_delete(api, issuing_ca_instance, encoding):
    """Imported CRLs retain their identity and round-trip through both download formats."""
    ca = issuing_ca_instance['issuing_ca']
    response = api.post('/api/crls/', {'ca': ca.pk, 'crl_file': crl_upload(issuing_ca_instance, encoding=encoding)})
    assert response.status_code == 201, response.data
    pk = response.data['id']
    assert response.data['is_active'] is True
    assert response.data['crl_number'] == 10
    assert api.get(f'/api/crls/{pk}/').status_code == 200
    for download_encoding in ('pem', 'der'):
        result = api.get(f'/api/crls/{pk}/download/?encoding={download_encoding}')
        assert result.status_code == 200
        parser = x509.load_pem_x509_crl if download_encoding == 'pem' else x509.load_der_x509_crl
        assert parser(result.content).issuer == issuing_ca_instance['cert'].subject
    assert api.get(f'/api/crls/{pk}/download/?encoding=invalid').status_code == 400
    assert api.delete(f'/api/crls/{pk}/').status_code == 204
    assert not CrlModel.objects.filter(pk=pk).exists()


def test_crl_rejects_bad_signature_and_malformed_file(api, issuing_ca_instance):
    """A CRL cannot be associated with a CA that did not sign it."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    response = api.post(
        '/api/crls/',
        {'ca': issuing_ca_instance['issuing_ca'].pk, 'crl_file': crl_upload(issuing_ca_instance, signing_key=key)},
    )
    assert response.status_code == 400
    assert not CrlModel.objects.exists()
    assert api.post('/api/crls/', {'crl_file': SimpleUploadedFile('bad.crl', b'invalid')}).status_code == 400


def test_crl_duplicate_does_not_deactivate_current(api, issuing_ca_instance):
    """A duplicate import rolls back changes to the active CRL."""
    ca = issuing_ca_instance['issuing_ca']
    assert api.post('/api/crls/', {'ca': ca.pk, 'crl_file': crl_upload(issuing_ca_instance)}).status_code == 201
    response = api.post('/api/crls/', {'ca': ca.pk, 'crl_file': crl_upload(issuing_ca_instance)})
    assert response.status_code == 409
    assert CrlModel.objects.filter(ca=ca, is_active=True).count() == 1


def test_unassociated_crl_is_inactive(api, issuing_ca_instance):
    """Unassociated CRLs can be retained without becoming an active CA CRL."""
    response = api.post('/api/crls/', {'crl_file': crl_upload(issuing_ca_instance)})
    assert response.status_code == 201
    assert response.data['ca'] is None
    assert response.data['is_active'] is False


def test_rollover_transitions_and_audit(api, ca, lab_config):
    """Valid transitions persist and emit the same audit operations as the UI."""
    from cryptography.hazmat.primitives.serialization import pkcs12

    cert, key = CertificateGenerator.create_root_ca(cn='Replacement')
    response = api.post(
        '/api/ca-rollovers/',
        {
            'old_issuing_ca': ca.pk,
            'method': 'pkcs12',
            'unique_name': 'replacement',
            'pkcs12_file': SimpleUploadedFile(
                'new-ca.p12',
                pkcs12.serialize_key_and_certificates(b'replacement', key, cert, None, serialization.NoEncryption()),
            ),
        },
    )
    assert response.status_code == 201, response.data
    rollover = CaRolloverModel.objects.get(pk=response.data['id'])
    count = CaModel.objects.count()
    duplicate = api.post(
        '/api/ca-rollovers/',
        {'old_issuing_ca': ca.pk, 'method': 'pkcs12', 'pkcs12_file': SimpleUploadedFile('invalid.p12', b'invalid')},
    )
    assert duplicate.status_code == 409
    assert CaModel.objects.count() == count
    url = f'/api/ca-rollovers/{rollover.pk}/'
    assert api.post(url + 'transition/').status_code == 409
    assert api.post(url + 'start/').status_code == 200
    assert api.post(url + 'start/').status_code == 409
    assert api.post(url + 'transition/').status_code == 200
    assert api.post(url + 'complete/').status_code == 200
    rollover.refresh_from_db()
    assert rollover.state == CaRolloverState.COMPLETED
    assert AuditLog.objects.filter(operation_type=AuditLog.OperationType.CA_ROLLOVER_COMPLETED).exists()
    assert api.patch(url, {'state': 'planned'}, format='json').status_code == 405


def test_rollover_cancel(api, ca):
    """Cancellation goes through the lifecycle service."""
    rollover = CaRolloverModel.objects.create(old_issuing_ca=ca, strategy_type=CaRolloverStrategyType.IMPORT_CA)
    assert api.post(f'/api/ca-rollovers/{rollover.pk}/cancel/').status_code == 200
    rollover.refresh_from_db()
    assert rollover.state == CaRolloverState.CANCELLED


def test_rollover_invalid_plan_rolls_back_import(api, ca):
    """Invalid strategy input must not leave pending CAs behind."""
    before = CaModel.objects.count()
    response = api.post(
        '/api/ca-rollovers/',
        {
            'old_issuing_ca': ca.pk,
            'method': 'pkcs12',
            'pkcs12_file': SimpleUploadedFile('bad.p12', b'not a credential'),
        },
    )
    assert response.status_code == 400
    assert CaModel.objects.count() == before


def test_generate_disabled_by_policy(api):
    """API clients cannot bypass the AutoGenPKI policy check."""
    with patch('pki.views.ca_api.IssuingCaAddAutoGenForm') as form:
        form.return_value.is_valid.return_value = True
        response = api.post('/api/issuing-cas/generate/', {'key_type': 'RSA-2048'}, format='json')
    assert response.status_code == 400


@pytest.fixture
def lab_config():
    """Allow the same management operations as the UI's laboratory policy."""
    config = SecurityConfig(security_mode=SecurityConfig.SecurityModeChoices.LAB)
    config.apply_security_settings(save=False)
    config.save()
    return config


@pytest.mark.parametrize('protocol', ['est', 'cmp'])
@pytest.mark.parametrize('is_ra_mode', [False, True])
def test_remote_ca_configuration(api, ca, lab_config, protocol, is_ra_mode):
    """Remote configuration uses validated UI forms and never returns authentication secrets."""
    data = {
        'unique_name': f'new-{protocol}-{is_ra_mode}',
        'key_type': 'RSA-2048',
        'remote_host': 'localhost',
        'remote_port': 443,
        'remote_path': f'/.well-known/{protocol}/enroll',
        'est_username': 'operator',
        'est_password': 'a-remote-password',
        'cmp_shared_secret': 'a-cmp-secret',
        'is_ra_mode': is_ra_mode,
    }
    response = api.post(f'/api/issuing-cas/configure-{protocol}/', data, format='json')
    assert response.status_code == 201, response.data
    created = CaModel.objects.get(pk=response.data['id'])
    assert (created.credential_id is None) is is_ra_mode
    assert 'est_password' not in response.data
    assert 'cmp_shared_secret' not in response.data
    assert api.post(f'/api/issuing-cas/{created.pk}/enroll/', {}, format='json').status_code == 400


def test_pkcs12_import_and_legacy_pem_import(api, ca, lab_config):
    """Both new PKCS#12 and existing PEM import contracts create real CAs."""
    from cryptography.hazmat.primitives.serialization import pkcs12

    for method in ('pkcs12', 'pem'):
        cert, key = CertificateGenerator.create_root_ca(cn=f'Imported-{method}')
        if method == 'pkcs12':
            data = {
                'pkcs12_file': SimpleUploadedFile(
                    'ca.p12',
                    pkcs12.serialize_key_and_certificates(b'imported', key, cert, None, serialization.NoEncryption()),
                )
            }
            response = api.post('/api/issuing-cas/import-pkcs12/', data)
        else:
            data = {
                'private_key_pem': key.private_bytes(
                    serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
                ).decode(),
                'ca_certificate_pem': cert.public_bytes(serialization.Encoding.PEM).decode(),
            }
            response = api.post('/api/issuing-cas/', data, format='json')
        assert response.status_code == 201, response.data
        assert CaModel.objects.get(pk=response.data['id']).get_certificate().serial_number == cert.serial_number


def test_external_csr_and_certificate_import(api, ca, lab_config):
    """Generate a managed CSR and accept only the matching issued CA certificate."""
    from django.core.management import call_command

    call_command('create_default_cert_profiles')
    response = api.post(
        '/api/issuing-cas/configure-external-csr/',
        {'unique_name': 'external-ca', 'key_type': 'RSA-2048'},
        format='json',
    )
    assert response.status_code == 201, response.data
    pk = response.data['id']
    response = api.post(
        f'/api/issuing-cas/{pk}/csr/',
        {
            'common_name': 'New Issuing CA',
            'organization_name': 'Example',
            'country_name': 'DE',
            'state_or_province_name': 'Berlin',
            'days': 30,
        },
        format='json',
    )
    assert response.status_code == 200, getattr(response, 'data', response.content)
    csr = x509.load_pem_x509_csr(response.content)
    assert csr.is_signature_valid
    now = timezone.now()
    cert = (
        x509.CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(ca.get_certificate().subject)
        .public_key(csr.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(ca.credential.get_private_key(), hashes.SHA256())
    )
    wrong = api.post(
        f'/api/issuing-cas/{pk}/import-certificate/',
        {'certificate': SimpleUploadedFile('wrong.pem', ca.get_certificate().public_bytes(serialization.Encoding.PEM))},
    )
    assert wrong.status_code == 400
    uploaded = api.post(
        f'/api/issuing-cas/{pk}/import-certificate/',
        {'certificate': SimpleUploadedFile('ca.pem', cert.public_bytes(serialization.Encoding.PEM))},
    )
    assert uploaded.status_code == 200, uploaded.data
    assert api.get(f'/api/issuing-cas/{pk}/certificate/').status_code == 200


def test_issuing_ca_cannot_be_patched_as_generic_model(api, ca):
    """Read-only representations must not pretend to accept generic configuration writes."""
    assert api.patch(f'/api/issuing-cas/{ca.pk}/', {'is_active': False}, format='json').status_code == 405


@pytest.mark.parametrize('protocol', ['est', 'cmp'])
def test_upstream_ca_enrollment(api, ca, lab_config, protocol):
    """Build/sign the real request, substituting only the upstream network response."""
    from django.core.management import call_command

    from pki.models.truststore import TruststoreModel, TruststoreOrderModel

    call_command('create_default_cert_profiles')
    response = api.post(
        f'/api/issuing-cas/configure-{protocol}/',
        {
            'unique_name': f'enrolled-{protocol}',
            'key_type': 'RSA-2048',
            'remote_host': 'localhost',
            'remote_port': 443,
            'remote_path': f'/.well-known/{protocol}/enroll',
            'est_username': 'operator',
            'est_password': 'remote-password',
            'cmp_shared_secret': 'cmp-secret',
        },
        format='json',
    )
    assert response.status_code == 201, response.data
    new_ca = CaModel.objects.get(pk=response.data['id'])
    usage = TruststoreModel.IntendedUsage.TLS if protocol == 'est' else TruststoreModel.IntendedUsage.ISSUING_CA_CHAIN
    store = TruststoreModel.objects.create(unique_name=f'upstream-{protocol}', intended_usage=usage)
    TruststoreOrderModel.objects.create(trust_store=store, certificate=ca.ca_certificate_model, order=0)
    response = api.post(f'/api/issuing-cas/{new_ca.pk}/truststore/', {'trust_store': store.pk}, format='json')
    assert response.status_code == 200, response.data
    now = timezone.now()
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, 'New CA')]))
        .issuer_name(ca.get_certificate().subject)
        .public_key(new_ca.credential.get_private_key().public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(ca.credential.get_private_key(), hashes.SHA256())
    )
    path = (
        'pki.services.ca_enrollment.EstClient.simple_enroll'
        if protocol == 'est'
        else 'pki.services.ca_enrollment.CmpClient.send_and_extract_certificate'
    )
    upstream_result = cert if protocol == 'est' else (cert, [ca.get_certificate()])
    with patch(path, return_value=upstream_result) as upstream:
        response = api.post(
            f'/api/issuing-cas/{new_ca.pk}/enroll/',
            {
                'common_name': 'New CA',
                'organization_name': 'Example',
                'country_name': 'DE',
                'state_or_province_name': 'Berlin',
                'days': 30,
            },
            format='json',
        )
    assert response.status_code == 200, response.data
    upstream.assert_called_once()
    new_ca.refresh_from_db()
    assert new_ca.get_certificate().serial_number == cert.serial_number


def test_ca_api_openapi_contract():
    """The generated schema exposes new actions and immutable CRL/rollover resources."""
    from django.urls import include, path
    from drf_spectacular.generators import SchemaGenerator

    schema = SchemaGenerator(patterns=[path('api/', include('pki.api_urls'))]).get_schema(public=True)
    paths = schema['paths']
    assert 'post' in paths['/api/issuing-cas/{id}/enroll/']
    assert 'post' in paths['/api/issuing-cas/{id}/import-certificate/']
    assert 'patch' in paths['/api/issuing-cas/{id}/crl-settings/']
    assert 'patch' not in paths['/api/issuing-cas/{id}/']
    assert 'post' in paths['/api/crls/']
    assert 'get' in paths['/api/crls/{id}/download/']
    assert 'post' in paths['/api/ca-rollovers/{id}/complete/']


def test_public_crl_url_name_is_preserved():
    """An API download must not shadow the existing public CRL URL name."""
    from django.urls import reverse

    assert reverse('crl-download', kwargs={'pk': 12}) == '/crl/12/'
    assert reverse('crl-api-download', kwargs={'pk': 12}) == '/api/crls/12/download/'


def test_remote_protocol_policy_denial_rolls_back(api, ca, lab_config):
    """Policy rejections return a client error and do not leave a configured CA behind."""
    lab_config.permitted_no_onboarding_pki_protocols = 0
    lab_config.save()
    response = api.post(
        '/api/issuing-cas/configure-est/',
        {
            'unique_name': 'forbidden-est',
            'key_type': 'RSA-2048',
            'remote_host': 'localhost',
            'remote_port': 443,
            'remote_path': '/.well-known/est/simpleenroll',
            'est_username': 'operator',
            'est_password': 'remote-password',
        },
        format='json',
    )
    assert response.status_code == 400, response.data
    assert not CaModel.objects.filter(unique_name='forbidden-est').exists()
