
# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Management external TLS CSR wizard integration and security tests."""

import json
from datetime import UTC, datetime, timedelta
from ipaddress import ip_address
from unittest.mock import Mock, patch

import pytest
from bs4 import BeautifulSoup
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from django.contrib.auth.models import AnonymousUser
from django.core.exceptions import PermissionDenied
from django.core.files.uploadedfile import SimpleUploadedFile
from django.core.management import call_command
from django.http import Http404
from django.template.loader import render_to_string
from django.test import RequestFactory
from django.urls import resolve, reverse

from management.forms import TlsExternalCsrKeyForm
from management.models import SecurityConfig
from pki.forms.truststores import TruststoreAddForm
from pki.models import CertificateModel, CredentialModel
from pki.models.cert_profile import CertificateProfileModel
from pki.models.credential import CertificateChainOrderModel, PrimaryCredentialCertificate
from pki.models.truststore import ActiveTrustpointTlsServerCredentialModel, TruststoreModel
from users.permissions import AppPermissions

pytestmark = pytest.mark.django_db


@pytest.fixture(autouse=True)
def profiles():
    call_command('create_default_cert_profiles')
    SecurityConfig.objects.create(security_mode=True, rsa_minimum_key_size=2048)


class Wizard:
    def __init__(self):
        self.session = {}
        self.user = Mock()
        self.user.has_perm.return_value = True
        self.factory = RequestFactory()

    def request(self, name, pk=None, method='get', data=None, query=''):
        url = reverse(f'management:{name}', kwargs={'pk': pk} if pk is not None else {}) + query
        request = getattr(self.factory, method)(url, data=data or {})
        request.user = self.user
        request.session = self.session
        match = resolve(url.split('?')[0])
        response = match.func(request, **match.kwargs)
        if hasattr(response, 'render'):
            response.render()
        return response

    def start(self, key_type='ECC-SECP256R1'):
        response = self.request('tls-external-csr-key', method='post', data={'key_type': key_type})
        assert response.status_code == 302
        pk = resolve(response.url).kwargs['pk']
        return CredentialModel.objects.get(pk=pk)

    def content(self, credential, truststore, data=None, profile=None):
        response = self.request('tls-external-csr-truststore', credential.pk, 'post', {'truststore': truststore.pk})
        assert response.status_code == 302
        values = {
            'common_name': 'server.example', 'organization_name': 'Example',
            'organizational_unit_name': 'Operations', 'country_name': 'DE',
            'state_or_province_name': 'BW', 'locality_name': 'Stuttgart',
            'email_address': 'ops@example.com', 'dns_names': 'server.example, second.example',
            'ip_addresses': '127.0.0.1, ::1', 'rfc822_names': 'ops@example.com',
            'uris': 'urn:example:server', 'days': 10,
        }
        values.update(data or {})
        if profile is not None:
            values['cert_profile_pk'] = profile.pk
        response = self.request('tls-external-csr-content', credential.pk, 'post', values)
        assert response.status_code == 302, response.context_data['form'].errors if response.status_code != 302 else ''
        return x509.load_pem_x509_csr(self.session[f'tls_external_csr_{credential.pk}']['csr_pem'].encode())


@pytest.fixture
def wizard():
    return Wizard()


def ca_certificate(key, subject, issuer_key=None, issuer=None, path_length=None, expired=False):
    now = datetime.now(UTC)
    signing_key = issuer_key or key
    return (
        x509.CertificateBuilder().subject_name(subject).issuer_name(issuer or subject)
        .public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=30))
        .not_valid_after(now + timedelta(days=-1 if expired else 365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=path_length), critical=True)
        .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(signing_key.public_key()), critical=False)
        .sign(signing_key, hashes.SHA256())
    )


@pytest.fixture
def pki_chain():
    root_key = ec.generate_private_key(ec.SECP256R1())
    root_name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, 'External Root')])
    root = ca_certificate(root_key, root_name)
    issuer_key = ec.generate_private_key(ec.SECP256R1())
    issuer_name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, 'External Issuer')])
    issuer = ca_certificate(issuer_key, issuer_name, root_key, root_name)
    truststore = TruststoreAddForm.save_trust_store('external-tls', TruststoreModel.IntendedUsage.TLS, [issuer, root])
    return root, issuer, issuer_key, truststore


def issue(csr, issuer, issuer_key, change=None):
    change = change or {}
    now = datetime.now(UTC)
    builder = (
        x509.CertificateBuilder().subject_name(change.get('subject', csr.subject)).issuer_name(issuer.subject)
        .public_key(change.get('key', csr.public_key())).serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=30)).not_valid_after(now + timedelta(days=change.get('days', 10)))
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(csr.public_key()), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()), critical=False)
    )
    for extension in csr.extensions:
        if extension.oid == x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME and change.get('missing_san'):
            continue
        value = extension.value
        if extension.oid == x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME and 'san' in change:
            value = change['san']
        if extension.oid == x509.ExtensionOID.BASIC_CONSTRAINTS and change.get('ca'):
            value = x509.BasicConstraints(ca=True, path_length=None)
        critical = extension.critical
        if extension.oid == x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME:
            critical = change.get('critical_san', not bool(csr.subject))
        builder = builder.add_extension(value, critical=critical)
    return builder.sign(issuer_key, hashes.SHA256())


def upload(wizard, credential, data):
    return wizard.request('tls-external-csr', credential.pk, 'post', {
        'certificate': SimpleUploadedFile('issued.cer', data),
    })


def test_method_selection_cards_share_existing_style():
    page = BeautifulSoup(render_to_string('management/tls/method_select.html'), 'html.parser')
    for route in (
        'tls-add-file_import-pkcs12', 'tls-add-file_import-separate_files',
        'tls-generate', 'tls-external-csr-key',
    ):
        option = page.select_one(f'a[href="{reverse(f"management:{route}")}"]')
        assert option.select_one('.card.h-100.shadow-sm') is not None
        assert option.select_one('.card-body.d-flex.flex-column') is not None
        assert option.select_one('p.text-muted') is not None
        assert option.select_one('.mt-auto .btn.btn-primary') is not None


def test_key_default_choices_and_capability_filter(wizard):
    response = wizard.request('tls-external-csr-key')
    page = BeautifulSoup(response.content, 'html.parser')
    assert page.select_one('h1').get_text(strip=True) == 'Add New TLS Certificate'
    assert page.select_one('h2').get_text(strip=True) == 'External PKI'
    assert page.select_one('.alert.alert-info.mb-4') is not None
    assert page.select_one('#tls-external-csr-key-form #div_id_key_type') is not None
    assert page.select_one('.tp-kvp-list') is None
    back = page.select_one('.card-footer a.btn-secondary')
    assert back['href'] == reverse('management:tls-add-method_select')
    assert back.get_text(strip=True) == 'Back'
    assert page.select_one('.card-footer button[form="tls-external-csr-key-form"]') is not None
    field = response.context_data['form'].fields['key_type']
    assert field.initial == 'ECC-SECP256R1'
    assert {value for value, label in field.choices} == {
        'RSA-2048', 'RSA-3072', 'RSA-4096', 'ECC-SECP256R1', 'ECC-SECP384R1',
    }
    with patch('pki.services.key_generation.get_active_backend_capability_report') as report:
        report.return_value.supports_key_spec.side_effect = lambda spec: getattr(spec, 'key_size', None) == 3072
        assert list(TlsExternalCsrKeyForm().fields['key_type'].choices) == [('RSA-3072', 'RSA 3072')]
        response = wizard.request('tls-external-csr-key', method='post', data={'key_type': 'ECC-SECP256R1'})
        assert response.status_code == 200
        assert CredentialModel.objects.count() == 0


@pytest.mark.parametrize('key_type', ['ECC-SECP256R1', 'RSA-2048'])
def test_pending_key_and_csr_extensions(wizard, pki_chain, key_type):
    credential = wizard.start(key_type)
    assert credential.certificate_id is None
    assert credential.private_key == ''
    assert credential.managed_private_key is not None
    assert credential.managed_private_key.policy_snapshot['extractable'] is True
    csr = wizard.content(credential, pki_chain[3])
    assert csr.is_signature_valid
    assert csr.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo) == (
        credential.get_private_key().public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    )
    for extension in (x509.BasicConstraints, x509.KeyUsage, x509.ExtendedKeyUsage, x509.SubjectAlternativeName):
        csr.extensions.get_extension_for_class(extension)
    assert csr.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value == x509.ExtendedKeyUsage([
        x509.ExtendedKeyUsageOID.SERVER_AUTH,
    ])
    assert csr.subject.get_attributes_for_oid(x509.NameOID.ORGANIZATIONAL_UNIT_NAME)[0].value == 'Operations'
    state = wizard.session[f'tls_external_csr_{credential.pk}']
    assert json.loads(json.dumps(state)) == state
    overview = wizard.request('tls-external-csr', credential.pk)
    assert 'TLS Server' in overview.content.decode()
    assert '<textarea' in overview.content.decode()
    assert 'certificate-upload-form' in overview.content.decode()
    page = BeautifulSoup(overview.content, 'html.parser')
    assert page.select_one('.card-header .badge').get_text(strip=True) == 'CSR'
    assert 'Certificate pending' in page.select_one('.card-body .alert').get_text()
    assert page.select_one('#copy-csr-button.btn-outline-primary') is not None
    assert 'Edit Certificate Content' in page.select_one('.card-footer').get_text()
    download = wizard.request('tls-external-csr', credential.pk, query='?download=1')
    assert download.content == csr.public_bytes(Encoding.PEM)
    assert download['Content-Type'] == 'application/pkcs10'
    assert download['Content-Disposition'].endswith('.csr"')
    assert CredentialModel.objects.count() == 1


def test_certificate_content_matches_issuance_layout(wizard):
    credential = wizard.start()
    response = wizard.request('tls-external-csr-content', credential.pk)
    page = BeautifulSoup(response.content, 'html.parser')
    assert len(page.select('h1')) == 1
    assert page.select_one('.card-header p.text-muted') is not None
    form = page.select_one('#tls-external-csr-configuration-form')
    assert [heading.get_text(strip=True) for heading in form.select('section h2')] == [
        'Certificate Profile', 'Subject', 'Subject Alternative Names', 'Validity Period',
    ]
    assert len(form.select('section .tp-kvp-list')) == 4
    assert form.select_one('#id_cert_profile_select.form-select') is not None
    for field in response.context_data['form']:
        if field.is_hidden:
            continue
        assert form.select_one(f'label[for="{field.id_for_label}"]') is not None
        assert form.select_one(f'[id="{field.id_for_label}"]') is not None
    assert page.select_one('.card-footer button[form="tls-external-csr-configuration-form"]') is not None


def test_application_profiles_only_and_explicit_invalid_rejected(wizard, pki_chain):
    credential = wizard.start()
    response = wizard.request('tls-external-csr-content', credential.pk)
    default = response.context_data['cert_profile']
    assert default.unique_name == 'tls_server'
    other = CertificateProfileModel.objects.create(
        unique_name='custom-tls', display_name='Custom TLS', profile_json=default.profile,
        credential_type=CertificateProfileModel.ProfileCredentialType.APPLICATION,
    )
    domain = CertificateProfileModel.objects.create(
        unique_name='domain-only', profile_json=default.profile,
        credential_type=CertificateProfileModel.ProfileCredentialType.DOMAIN,
    )
    response = wizard.request('tls-external-csr-content', credential.pk, query=f'?cert_profile_pk={other.pk}')
    assert response.context_data['cert_profile'].pk == other.pk
    assert all(p.credential_type == 'application' for p in response.context_data['available_profiles'])
    assert 'domain-only' not in response.content.decode()
    for value in ('invalid', '9999999', str(domain.pk)):
        for method in ('get', 'post'):
            with pytest.raises(Http404):
                wizard.request('tls-external-csr-content', credential.pk, method, {'cert_profile_pk': value},
                               query=f'?cert_profile_pk={value}' if method == 'get' else '')
    wizard.content(credential, pki_chain[3], profile=other)
    assert wizard.session[f'tls_external_csr_{credential.pk}']['profile_pk'] == other.pk


@pytest.mark.parametrize('encoding', [Encoding.PEM, Encoding.DER])
def test_finalizes_same_key_chain_inactive_and_visible(wizard, pki_chain, encoding):
    root, issuer, issuer_key, truststore = pki_chain
    credential = wizard.start()
    original_key_id = credential.managed_private_key_id
    csr = wizard.content(credential, truststore)
    other = wizard.start()
    other_state = wizard.session[f'tls_external_csr_{other.pk}'].copy()
    wizard.session['unrelated'] = {'preserve': True}
    certificate = issue(csr, issuer, issuer_key)
    response = upload(wizard, credential, certificate.public_bytes(encoding))
    assert response.status_code == 302, response.context_data['form'].errors if response.status_code != 302 else ''
    assert response.url == reverse('management:tls')
    credential.refresh_from_db()
    assert credential.managed_private_key_id == original_key_id
    assert credential.private_key == ''
    assert PrimaryCredentialCertificate.objects.get(credential=credential).certificate_id == credential.certificate_id
    chain = list(CertificateChainOrderModel.objects.filter(credential=credential).order_by('order'))
    assert [item.certificate.get_certificate_serializer().as_crypto() for item in chain] == [root, issuer]
    assert all(item.primary_certificate_id == credential.certificate_id for item in chain)
    assert not ActiveTrustpointTlsServerCredentialModel.objects.exists()
    assert CertificateModel.objects.filter(credential=credential).get().pk == credential.certificate_id
    assert f'tls_external_csr_{credential.pk}' not in wizard.session
    assert wizard.session[f'tls_external_csr_{other.pk}'] == other_state
    assert wizard.session['unrelated'] == {'preserve': True}
    overview = wizard.request('tls')
    assert credential.certificate in overview.context_data['tls_certificates']
    with pytest.raises(Http404):
        wizard.request('tls-external-csr', credential.pk)


@pytest.mark.parametrize('problem', [
    'wrong_key', 'ca', 'untrusted', 'subject', 'extra_san', 'missing_san', 'different_san',
    'bundle', 'malformed', 'expired', 'expired_issuer', 'path_length', 'ca_key_usage', 'critical_san',
])
def test_rejects_invalid_issued_leaf(wizard, pki_chain, problem):
    root, issuer, issuer_key, truststore = pki_chain
    credential = wizard.start()
    csr = wizard.content(credential, truststore)
    change = {}
    if problem == 'wrong_key':
        change['key'] = ec.generate_private_key(ec.SECP256R1()).public_key()
    elif problem == 'ca':
        change['ca'] = True
    elif problem == 'subject':
        change['subject'] = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, 'wrong.example')])
    elif problem == 'extra_san':
        change['san'] = x509.SubjectAlternativeName([
            *csr.extensions.get_extension_for_class(x509.SubjectAlternativeName).value, x509.DNSName('extra.example'),
        ])
    elif problem == 'missing_san':
        change['missing_san'] = True
    elif problem == 'different_san':
        change['san'] = x509.SubjectAlternativeName([x509.DNSName('wrong.example')])
    elif problem == 'expired':
        change['days'] = -1
    elif problem == 'critical_san':
        change['critical_san'] = True
    elif problem == 'untrusted':
        issuer_key = ec.generate_private_key(ec.SECP256R1())
        issuer = ca_certificate(issuer_key, issuer.subject)
    elif problem in ('expired_issuer', 'path_length', 'ca_key_usage'):
        root_key = ec.generate_private_key(ec.SECP256R1())
        root = ca_certificate(root_key, root.subject, path_length=0 if problem == 'path_length' else None)
        issuer = ca_certificate(issuer_key, issuer.subject, root_key, root.subject, expired=problem == 'expired_issuer')
        if problem == 'ca_key_usage':
            issuer = (
                x509.CertificateBuilder().subject_name(issuer.subject).issuer_name(root.subject)
                .public_key(issuer_key.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(issuer.not_valid_before_utc).not_valid_after(issuer.not_valid_after_utc)
                .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
                .add_extension(x509.KeyUsage(True, False, False, False, False, False, False, False, False), critical=True)
                .sign(root_key, hashes.SHA256())
            )
        new_store = TruststoreAddForm.save_trust_store('invalid-chain', TruststoreModel.IntendedUsage.TLS, [issuer, root])
        wizard.session[f'tls_external_csr_{credential.pk}']['truststore_pk'] = new_store.pk
    certificate = issue(csr, issuer, issuer_key, change)
    data = certificate.public_bytes(Encoding.PEM)
    if problem == 'bundle':
        data += issuer.public_bytes(Encoding.PEM)
    if problem == 'malformed':
        data = b'not a certificate'
    response = upload(wizard, credential, data)
    assert response.status_code == 200
    assert response.context_data['form'].errors
    credential.refresh_from_db()
    assert credential.certificate_id is None
    assert not PrimaryCredentialCertificate.objects.filter(credential=credential).exists()
    assert f'tls_external_csr_{credential.pk}' in wizard.session


def test_truststore_import_uses_existing_form(wizard, pki_chain):
    credential = wizard.start()
    root, issuer, issuer_key, truststore = pki_chain
    response = wizard.request('tls-external-csr-truststore', credential.pk, 'post', {
        'import_truststore': '1', 'unique_name': 'imported-tls',
        'intended_usage': TruststoreModel.IntendedUsage.TLS,
        'trust_store_file': SimpleUploadedFile('chain.pem', issuer.public_bytes(Encoding.PEM) + root.public_bytes(Encoding.PEM)),
    })
    assert response.status_code == 302
    imported = TruststoreModel.objects.get(unique_name='imported-tls')
    response = wizard.request('tls-external-csr-truststore', credential.pk, query=f'?truststore_id={imported.pk}')
    assert response.context_data['form'].initial['truststore'] == str(imported.pk)


@pytest.mark.parametrize('step', ['tls-external-csr-key', 'tls-external-csr-truststore', 'tls-external-csr-content', 'tls-external-csr'])
@pytest.mark.parametrize('method', ['get', 'post'])
@pytest.mark.parametrize('anonymous', [False, True])
def test_all_steps_require_tls_permission(wizard, step, method, anonymous):
    wizard.user = AnonymousUser() if anonymous else Mock()
    if not anonymous:
        wizard.user.has_perm.return_value = False
    with pytest.raises(PermissionDenied):
        wizard.request(step, None if step.endswith('-key') else 999, method)
    if not anonymous:
        wizard.user.has_perm.assert_called_with(AppPermissions.MANAGE_TLS_WEBSERVER_CONFIGURATION)
    assert CredentialModel.objects.count() == 0


def test_download_permission_and_foreign_session_isolation(wizard, pki_chain):
    credential = wizard.start()
    wizard.content(credential, pki_chain[3])
    second = Wizard()
    foreign = second.start()
    for step in ('tls-external-csr-truststore', 'tls-external-csr-content', 'tls-external-csr'):
        for method in ('get', 'post'):
            with pytest.raises(Http404):
                second.request(step, credential.pk, method)
    with pytest.raises(Http404):
        second.request('tls-external-csr', credential.pk, query='?download=1')
    second.session[f'tls_external_csr_{credential.pk}'] = second.session[f'tls_external_csr_{foreign.pk}']
    with pytest.raises(Http404):
        second.request('tls-external-csr', credential.pk, query='?download=1')
    wizard.user.has_perm.return_value = False
    with pytest.raises(PermissionDenied):
        wizard.request('tls-external-csr', credential.pk, query='?download=1')


def test_ip_only_identity_is_fully_verified(wizard, pki_chain):
    profile = CertificateProfileModel.objects.get(unique_name='tls_server')
    definition = profile.profile
    definition['ext']['subject_alternative_name']['dns_names'] = {'default': []}
    profile.profile_json = definition
    profile.save()
    credential = wizard.start()
    csr = wizard.content(credential, pki_chain[3], data={
        'dns_names': '', 'ip_addresses': '192.0.2.10', 'rfc822_names': '', 'uris': '',
    })
    assert list(csr.extensions.get_extension_for_class(x509.SubjectAlternativeName).value) == [
        x509.IPAddress(ip_address('192.0.2.10')),
    ]
    certificate = issue(csr, pki_chain[1], pki_chain[2])
    assert upload(wizard, credential, certificate.public_bytes(Encoding.PEM)).status_code == 302