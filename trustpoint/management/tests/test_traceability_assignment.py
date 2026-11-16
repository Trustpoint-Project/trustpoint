# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Credential assignment, replacement validation, and persistent CSR regressions."""

import datetime as dt
from unittest.mock import patch

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID
from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.core.files.uploadedfile import SimpleUploadedFile
from django.core.management import call_command
from django.db import IntegrityError, transaction
from django.urls import reverse

from crypto.application.service import TrustpointCryptoBackend
from management.models import SecurityConfig
from management.models.traceability import TraceabilityCredentialGenerationModel, TraceabilityCredentialModel
from management.services.traceability_signing import TraceabilityCredentialService as Service
from management.views.traceability_signing import TraceabilityCredentialSettingsForm
from pki.forms.truststores import TruststoreAddForm
from pki.models import CaModel, CertificateProfileModel, CredentialModel, TruststoreModel
from pki.services.management_issuance import sign_certificate_request

pytestmark = pytest.mark.django_db
Method = TraceabilityCredentialModel.AssignmentMethod
Curve = TraceabilityCredentialModel.Curve


@pytest.fixture(autouse=True)
def profiles():
    call_command('create_default_cert_profiles')


@pytest.fixture
def identity():
    return Service.configure(name='external-evidence', curve=Curve.SECP256R1, assignment_method=Method.CSR)


@pytest.fixture
def admin(client):
    client.force_login(get_user_model().objects.create_superuser(username='evidence-admin', password='test-password'))
    return client


def signed_certificate(ca, key, *, ca_leaf=False, signing=True, subject='external-evidence', expired=False, eku=None):
    now = dt.datetime.now(dt.UTC)
    builder = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, subject)]))
        .issuer_name(ca.get_certificate().subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=2))
        .not_valid_after(now + dt.timedelta(days=-1 if expired else 10))
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca.get_certificate().public_key()), critical=False
        )
        .add_extension(x509.BasicConstraints(ca=ca_leaf, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(signing, False, False, False, False, False, False, False, False), critical=True)
    )
    if eku is not None:
        builder = builder.add_extension(x509.ExtendedKeyUsage(eku), critical=False)
    return builder.sign(ca.credential.get_private_key(), hashes.SHA256())


def truststore(ca):
    existing = TruststoreModel.objects.filter(unique_name='traceability-anchors').first()
    if existing is not None:
        return existing
    return TruststoreAddForm.save_trust_store(
        'traceability-anchors',
        TruststoreModel.IntendedUsage.ISSUING_CA_CHAIN,
        [ca.get_certificate()],
    )


def enable_import():
    config = SecurityConfig.objects.first() or SecurityConfig()
    config.allow_imported_private_keys = True
    config.save()


def test_configuration_has_no_key_or_certificate(identity):
    assert identity.status == 'UNASSIGNED'
    assert not identity.is_usable
    assert identity.current_generation_id is None
    assert identity.pending_credential_id is None
    assert identity.generations.count() == 0
    with pytest.raises(ValidationError, match='not currently usable'):
        Service.sign(traceability_credential=identity, data=b'audit')


def test_management_assignment_requires_a_management_ca(traceability_management_ca):
    form = TraceabilityCredentialSettingsForm(
        assignment_method=Method.MANAGEMENT_CA,
        data={
            'name': 'a',
            'curve': Curve.SECP256R1,
            'assignment_method': Method.MANAGEMENT_CA,
        },
    )
    assert not form.is_valid()
    assert 'management_ca' in form.errors
    with pytest.raises(ValidationError, match='active management CA'):
        Service.configure(name='a', curve=Curve.SECP256R1, assignment_method=Method.MANAGEMENT_CA)
    traceability_management_ca.ca_role = CaModel.CaRole.ISSUING
    traceability_management_ca.save()
    with pytest.raises(ValidationError, match='active management CA'):
        Service.configure(
            name='a',
            curve=Curve.SECP256R1,
            assignment_method=Method.MANAGEMENT_CA,
            management_ca=traceability_management_ca,
        )


def test_local_management_ca_issues_and_rotates(traceability_management_ca):
    logical = Service.create(name='local-evidence', management_ca=traceability_management_ca)
    old = logical.current_generation
    old_certificate = old.credential.get_certificate()
    old_certificate.verify_directly_issued_by(traceability_management_ca.get_certificate())
    assert old.credential.get_certificate_chain() == [traceability_management_ca.get_certificate()]
    generation = Service.rotate(traceability_credential=logical)
    assert generation.credential.managed_private_key_id != old.credential.managed_private_key_id
    assert generation.credential.get_certificate().serial_number != old_certificate.serial_number
    old.refresh_from_db()
    assert old.status == 'RETIRED'
    assert TraceabilityCredentialGenerationModel.objects.filter(status='ACTIVE').count() == 1
    Service.retire(logical)
    with pytest.raises(ValidationError, match='not currently usable'):
        Service.sign(traceability_credential=logical, data=b'audit')
    fresh = Service.rotate(traceability_credential=logical)
    assert fresh.generation_number == 3
    logical.refresh_from_db()
    assert logical.is_usable and logical.retired_at is None


def test_failed_rotation_preserves_current_generation(traceability_management_ca):
    logical = Service.create(name='local-evidence', management_ca=traceability_management_ca)
    previous = logical.current_generation_id
    with patch(
        'management.services.traceability_signing.sign_certificate_request', side_effect=ValueError('unavailable')
    ):
        with pytest.raises(ValueError, match='unavailable'):
            Service.rotate(traceability_credential=logical)
    logical.refresh_from_db()
    assert logical.current_generation_id == previous
    assert logical.is_usable
    assert logical.generations.count() == 1


def test_csr_completion_and_cancel_use_fresh_keys(identity, traceability_management_ca):
    pem = Service.request_credential(identity, content={'common_name': identity.name})
    identity.refresh_from_db()
    old_pending = identity.pending_credential
    old_pending.full_clean()
    assert identity.current_generation_id is None
    with pytest.raises(ValidationError, match='already pending'):
        Service.request_credential(identity, content={'common_name': identity.name})
    with transaction.atomic():
        Service.cancel_csr(identity)
    Service.request_credential(identity, content={'common_name': identity.name})
    identity.refresh_from_db()
    assert old_pending.managed_private_key_id != identity.pending_credential.managed_private_key_id
    csr = x509.load_pem_x509_csr(identity.pending_csr.encode())
    certificate, _ = sign_certificate_request(
        csr,
        CertificateProfileModel.objects.get(unique_name='traceability_credential'),
        traceability_management_ca,
    )
    generation = Service.complete_csr(
        identity, certificate=certificate, truststore=truststore(traceability_management_ca)
    )
    identity.refresh_from_db()
    assert identity.is_usable and not identity.pending_csr and identity.pending_credential_id is None
    signature = Service.sign(traceability_credential=identity, data=b'audit')
    assert Service.verify(generation=generation, data=b'audit', signature=signature.signature).valid
    Service.request_credential(identity, content={'common_name': identity.name})
    identity.refresh_from_db()
    assert identity.is_usable
    Service.retire(identity)
    identity.refresh_from_db()
    assert not identity.pending_csr
    assert not identity.is_usable
    with pytest.raises(ValidationError, match='no pending'):
        Service.complete_csr(identity, certificate=certificate, truststore=truststore(traceability_management_ca))


def test_bad_csr_certificate_leaves_request_pending(identity, traceability_management_ca):
    Service.request_credential(identity, content={'common_name': identity.name})
    identity.refresh_from_db()
    certificate = signed_certificate(traceability_management_ca, ec.generate_private_key(ec.SECP256R1()))
    with pytest.raises(ValidationError, match='does not match the pending key'):
        Service.complete_csr(identity, certificate=certificate, truststore=truststore(traceability_management_ca))
    identity.refresh_from_db()
    assert identity.pending_credential_id and identity.pending_credential.certificate_id is None
    assert not identity.is_usable


def test_only_one_active_identity_even_for_direct_database_writes(traceability_management_ca):
    logical = Service.create(name='active', management_ca=traceability_management_ca)
    other = Service.configure(name='other', curve=Curve.SECP256R1, assignment_method=Method.CSR)
    with pytest.raises(ValidationError, match='Only one'):
        Service.request_credential(other, content={'common_name': other.name})
    with pytest.raises(IntegrityError), transaction.atomic():
        TraceabilityCredentialModel.objects.filter(pk=other.pk).update(status='ACTIVE')
    Service.retire(logical)
    assert isinstance(Service.request_credential(other, content={'common_name': other.name}), str)


@pytest.mark.parametrize('method', [Method.PKCS12, Method.SEPARATE_FILES])
def test_import_rotates_both_key_and_certificate(method, traceability_management_ca):
    enable_import()
    logical = Service.configure(name='imported', curve=Curve.SECP256R1, assignment_method=method)
    key = ec.generate_private_key(ec.SECP256R1())
    certificate = signed_certificate(traceability_management_ca, key)
    first = Service.import_credential(logical, private_key=key, certificate=certificate, chain=[])
    assert first.credential.private_key == ''
    assert first.credential.managed_private_key_id
    with pytest.raises(ValidationError, match='new key and certificate'):
        Service.import_credential(logical, private_key=key, certificate=certificate, chain=[])
    reissued = signed_certificate(traceability_management_ca, key)
    with pytest.raises(ValidationError, match='new key and certificate'):
        Service.import_credential(logical, private_key=key, certificate=reissued, chain=[])
    key2 = ec.generate_private_key(ec.SECP256R1())
    replacement = signed_certificate(traceability_management_ca, key2)
    second = Service.import_credential(logical, private_key=key2, certificate=replacement, chain=[])
    first.refresh_from_db()
    assert first.status == 'RETIRED'
    assert first.credential.managed_private_key_id != second.credential.managed_private_key_id
    signed = Service.sign(traceability_credential=logical, data=b'audit')
    assert Service.verify(generation=second, data=b'audit', signature=signed.signature).valid


@pytest.mark.parametrize('bad', ['ca', 'usage', 'expired', 'mismatch', 'curve'])
def test_import_rejects_invalid_credentials_before_backend_import(bad, traceability_management_ca):
    logical = Service.configure(name='invalid', curve=Curve.SECP256R1, assignment_method=Method.SEPARATE_FILES)
    key = ec.generate_private_key(ec.SECP384R1() if bad == 'curve' else ec.SECP256R1())
    certificate = signed_certificate(
        traceability_management_ca, key, ca_leaf=bad == 'ca', signing=bad != 'usage', expired=bad == 'expired'
    )
    if bad == 'mismatch':
        key = ec.generate_private_key(ec.SECP256R1())
    with patch.object(TrustpointCryptoBackend, 'import_managed_private_key') as backend_import:
        with pytest.raises(ValidationError):
            Service.import_credential(logical, private_key=key, certificate=certificate, chain=[])
        backend_import.assert_not_called()
    assert logical.generations.count() == 0


def test_full_csr_browser_flow_keeps_secrets_out_of_session(admin, traceability_management_ca):
    response = admin.post(
        reverse('management:traceability_credential_configure', kwargs={'method': Method.CSR}),
        {
            'name': 'external-evidence',
            'curve': Curve.SECP256R1,
            'assignment_method': Method.CSR,
        },
    )
    assert response.status_code == 302
    logical = TraceabilityCredentialModel.objects.get(name='external-evidence')
    url = reverse('management:traceability_credential_rotate', kwargs={'pk': logical.pk})
    response = admin.post(url, {'common_name': logical.name})
    assert response.status_code == 302
    logical.refresh_from_db()
    assert logical.pending_csr
    response = admin.get(url)
    assert response.status_code == 200
    assert 'Download CSR' in response.content.decode()
    download = admin.get(url + '?download=1')
    assert download.content == logical.pending_csr.encode()
    assert not any('traceability' in key for key in admin.session.keys())
    csr = x509.load_pem_x509_csr(download.content)
    certificate, _ = sign_certificate_request(
        csr,
        CertificateProfileModel.objects.get(unique_name='traceability_credential'),
        traceability_management_ca,
    )
    response = admin.post(
        url,
        {
            'certificate': SimpleUploadedFile('issued.pem', certificate.public_bytes(serialization.Encoding.PEM)),
            'truststore': truststore(traceability_management_ca).pk,
        },
    )
    assert response.status_code == 302
    logical.refresh_from_db()
    assert logical.is_usable


@pytest.mark.parametrize('method', [Method.PKCS12, Method.SEPARATE_FILES])
def test_upload_view_activates_imported_material(method, admin, traceability_management_ca):
    from cryptography.hazmat.primitives.serialization import pkcs12

    enable_import()
    logical = Service.configure(name='upload', curve=Curve.SECP256R1, assignment_method=method)
    key = ec.generate_private_key(ec.SECP256R1())
    certificate = signed_certificate(traceability_management_ca, key)
    url = reverse('management:traceability_credential_rotate', kwargs={'pk': logical.pk})
    if method == Method.PKCS12:
        data = {
            'pkcs12': SimpleUploadedFile(
                'credential.p12',
                pkcs12.serialize_key_and_certificates(
                    b'evidence',
                    key,
                    certificate,
                    None,
                    serialization.BestAvailableEncryption(b'password'),
                ),
            ),
            'password': 'password',
        }
    else:
        data = {
            'private_key': SimpleUploadedFile(
                'key.pem',
                key.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.PKCS8,
                    serialization.NoEncryption(),
                ),
            ),
            'certificate': SimpleUploadedFile('cert.pem', certificate.public_bytes(serialization.Encoding.PEM)),
        }
    response = admin.post(url, data)
    assert response.status_code == 302, response.context['form'].errors
    logical.refresh_from_db()
    assert logical.is_usable


@pytest.mark.parametrize(
    'ca_type,protocol',
    [
        (CaModel.CaTypeChoice.REMOTE_EST_RA, 'est'),
        (CaModel.CaTypeChoice.REMOTE_CMP_RA, 'cmp'),
    ],
)
def test_management_ra_uses_existing_enrollment_and_validates_response(ca_type, protocol, traceability_management_ca):
    from onboarding.models import NoOnboardingConfigModel, NoOnboardingPkiProtocol
    from pki.services.external_csr import build_external_csr

    anchors = truststore(traceability_management_ca)
    config = NoOnboardingConfigModel.objects.create(
        pki_protocols=NoOnboardingPkiProtocol.EST_USERNAME_PASSWORD
        if protocol == 'est'
        else NoOnboardingPkiProtocol.CMP_SHARED_SECRET,
        trust_store=anchors,
        est_password='test-password' if protocol == 'est' else '',
        cmp_shared_secret='test-secret' if protocol == 'cmp' else '',
    )
    remote = CaModel.objects.create(
        unique_name='Remote management RA',
        ca_type=ca_type,
        ca_role=CaModel.CaRole.MANAGEMENT,
        certificate=traceability_management_ca.credential.certificate,
        remote_host='pki.example',
        remote_port=8443,
        remote_path='/enroll',
        no_onboarding_config=config,
    )

    def enroll(context, **kwargs):
        # Only the protocol transport is mocked; keys, issuance and path validation are real.
        csr = build_external_csr(
            context.owner_credential,
            context.certificate_profile_model,
            {'common_name': 'remote-evidence'},
        )
        return sign_certificate_request(csr, context.certificate_profile_model, traceability_management_ca)

    with patch(f'pki.services.tls_server_issuance.enroll_{protocol}', side_effect=enroll) as endpoint:
        logical = Service.create(name='remote-evidence', management_ca=remote)
    assert logical.is_usable
    endpoint.assert_called_once()
    context = endpoint.call_args.args[0]
    assert getattr(context, f'{protocol}_server_host') == 'pki.example'
    logical.current_generation.credential.get_certificate().verify_directly_issued_by(
        traceability_management_ca.get_certificate(),
    )


def test_rotation_and_csr_download_require_management_permission(identity, client):
    client.force_login(get_user_model().objects.create_user(username='reader'))
    url = reverse('management:traceability_credential_rotate', kwargs={'pk': identity.pk})
    assert client.get(url).status_code == 403
    assert client.get(url + '?download=1').status_code == 403
    assert client.post(url, {'common_name': identity.name}).status_code == 403
    identity.refresh_from_db()
    assert not identity.pending_csr


def test_cancellation_destroys_only_the_pending_key(identity, django_capture_on_commit_callbacks):
    from crypto.models import CryptoManagedKeyModel

    Service.request_credential(identity, content={'common_name': identity.name})
    identity.refresh_from_db()
    pending_id = identity.pending_credential_id
    key_id = identity.pending_credential.managed_private_key_id
    with django_capture_on_commit_callbacks(execute=True):
        Service.cancel_csr(identity)
    assert not CredentialModel.objects.filter(pk=pending_id).exists()
    assert not CryptoManagedKeyModel.objects.filter(pk=key_id).exists()


def test_creation_starts_with_method_cards(admin):
    response = admin.get(reverse('management:traceability_credential_create'))
    assert response.status_code == 200
    assert b'id="traceability-credential-form"' not in response.content
    for method in Method.values:
        assert (
            reverse('management:traceability_credential_configure', kwargs={'method': method}).encode()
            in response.content
        )


@pytest.mark.parametrize('method', Method.values)
def test_configuration_only_shows_fields_for_selected_method(method, admin):
    response = admin.get(reverse('management:traceability_credential_configure', kwargs={'method': method}))
    assert response.status_code == 200
    fields = response.context['form'].fields
    assert 'assignment_method' not in fields
    assert ('management_ca' in fields) == (method == Method.MANAGEMENT_CA)
    assert ('curve' in fields) == (method == Method.CSR)
    assert list(fields)[:2] == ['name', 'description']
    assert b'Back to methods' in response.content


@pytest.mark.parametrize('method', [Method.PKCS12, Method.SEPARATE_FILES])
def test_import_configuration_ignores_generated_key_settings(method, admin, traceability_management_ca):
    enable_import()
    response = admin.post(
        reverse('management:traceability_credential_configure', kwargs={'method': method}),
        {
            'name': 'automatic-curve',
            'assignment_method': Method.MANAGEMENT_CA,
            'curve': Curve.SECP256R1,
            'management_ca': traceability_management_ca.pk,
        },
    )
    assert response.status_code == 302
    logical = TraceabilityCredentialModel.objects.get(name='automatic-curve')
    assert logical.assignment_method == method and not logical.curve and logical.management_ca_id is None
    logical.full_clean()
    key = ec.generate_private_key(ec.SECP384R1())
    certificate = signed_certificate(traceability_management_ca, key)
    Service.import_credential(logical, private_key=key, certificate=certificate, chain=[])
    logical.refresh_from_db()
    assert logical.curve == Curve.SECP384R1 and logical.is_usable
    signature = Service.sign(traceability_credential=logical, data=b'audit')
    assert Service.verify(generation=logical.current_generation, data=b'audit', signature=signature.signature).valid


def test_generated_key_configuration_requires_curve(admin):
    response = admin.post(
        reverse('management:traceability_credential_configure', kwargs={'method': Method.CSR}),
        {
            'name': 'needs-curve',
        },
    )
    assert response.status_code == 200
    assert 'curve' in response.context['form'].errors
    assert not TraceabilityCredentialModel.objects.filter(name='needs-curve').exists()


@pytest.mark.parametrize('traceability_curve', [Curve.SECP256R1, Curve.SECP384R1])
def test_management_ca_determines_curve_even_when_a_different_curve_is_submitted(
    traceability_curve,
    traceability_management_ca,
    admin,
):
    response = admin.post(
        reverse('management:traceability_credential_configure', kwargs={'method': Method.MANAGEMENT_CA}),
        {
            'name': 'ca-bound',
            'management_ca': traceability_management_ca.pk,
            'curve': Curve.SECP384R1 if traceability_curve == Curve.SECP256R1 else Curve.SECP256R1,
        },
    )
    assert response.status_code == 302
    logical = TraceabilityCredentialModel.objects.get(name='ca-bound')
    assert logical.curve == traceability_curve
    Service.request_credential(logical, content={'common_name': logical.name})
    logical.refresh_from_db()
    assert logical.current_generation.credential.get_certificate().public_key().curve.name == (
        traceability_management_ca.get_certificate().public_key().curve.name
    )


def test_management_ca_service_ignores_an_independent_curve(traceability_management_ca):
    logical = Service.configure(
        name='ca-bound',
        curve=Curve.SECP384R1,
        assignment_method=Method.MANAGEMENT_CA,
        management_ca=traceability_management_ca,
    )
    assert logical.curve == Curve.SECP256R1
    with patch.object(Service, 'management_ca_curve', return_value=Curve.SECP384R1):
        with patch('management.services.traceability_signing.generate_managed_signing_private_key') as generate:
            with pytest.raises(ValidationError, match='no longer matches'):
                Service.request_credential(logical, content={'common_name': logical.name})
            generate.assert_not_called()


def test_management_assignment_rejects_unsupported_ca_key(traceability_management_ca, admin):
    from crypto.models import CryptoManagedKeyModel
    from pki.tests.managed_ca_helpers import create_managed_root_ca

    certificate, key = create_managed_root_ca('RSA Management CA')
    traceability_management_ca.credential = CredentialModel.save_managed_key_credential(
        certificate=certificate,
        certificate_chain=[],
        credential_type=CredentialModel.CredentialTypeChoice.ISSUING_CA,
        managed_key=CryptoManagedKeyModel.objects.get(pk=key.managed_key_ref.id),
    )
    traceability_management_ca.save()
    response = admin.post(
        reverse('management:traceability_credential_configure', kwargs={'method': Method.MANAGEMENT_CA}),
        {
            'name': 'unsupported',
            'management_ca': traceability_management_ca.pk,
        },
    )
    assert response.status_code == 200
    assert 'P-256 or P-384' in str(response.context['form'].errors['management_ca'])
    assert not TraceabilityCredentialModel.objects.filter(name='unsupported').exists()


@pytest.mark.parametrize(
    'eku',
    [
        None,
        [ExtendedKeyUsageOID.ANY_EXTENDED_KEY_USAGE],
        [ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.ANY_EXTENDED_KEY_USAGE],
    ],
)
def test_import_accepts_eku_that_permits_traceability_signing(eku, traceability_management_ca):
    enable_import()
    logical = Service.configure(name='eku-import', assignment_method=Method.PKCS12)
    key = ec.generate_private_key(ec.SECP256R1())
    certificate = signed_certificate(traceability_management_ca, key, eku=eku)
    generation = Service.import_credential(logical, private_key=key, certificate=certificate, chain=[])
    signature = Service.sign(traceability_credential=logical, data=b'audit')
    assert Service.verify(generation=generation, data=b'audit', signature=signature.signature).valid


@pytest.mark.parametrize(
    'eku',
    [
        [],
        [ExtendedKeyUsageOID.CLIENT_AUTH],
        [ExtendedKeyUsageOID.SERVER_AUTH],
        [ExtendedKeyUsageOID.CODE_SIGNING],
        [x509.ObjectIdentifier('1.3.6.1.4.1.55555.1')],
    ],
)
def test_import_rejects_eku_without_a_permitted_traceability_purpose(eku, traceability_management_ca):
    logical = Service.configure(name='restricted-eku', assignment_method=Method.SEPARATE_FILES)
    key = ec.generate_private_key(ec.SECP256R1())
    certificate = signed_certificate(traceability_management_ca, key, eku=eku)
    with patch.object(TrustpointCryptoBackend, 'import_managed_private_key') as backend_import:
        with pytest.raises(
            ValidationError,
            match='Extended Key Usage must permit traceability signing'
            if eku
            else 'Invalid traceability certificate extensions',
        ):
            Service.import_credential(logical, private_key=key, certificate=certificate, chain=[])
        backend_import.assert_not_called()
    logical.refresh_from_db()
    assert logical.current_generation_id is None


@pytest.mark.parametrize('usage', ['any_extended_key_usage', 'anyExtendedKeyUsage', '2.5.29.37.0'])
def test_management_issuance_accepts_unrestricted_eku_profile(usage, traceability_management_ca):
    profile = CertificateProfileModel.objects.get(unique_name='traceability_credential')
    definition = profile.profile
    definition['ext']['extended_key_usage'] = {'usages': [usage]}
    profile.profile_json = definition
    profile.save()
    logical = Service.create(name='eku-issued', management_ca=traceability_management_ca)
    eku = (
        logical.current_generation.credential.get_certificate()
        .extensions.get_extension_for_class(
            x509.ExtendedKeyUsage,
        )
        .value
    )
    assert ExtendedKeyUsageOID.ANY_EXTENDED_KEY_USAGE in eku
    assert logical.is_usable


@pytest.mark.parametrize(
    'eku',
    [
        {'usages': ['server_auth']},
        {'usages': []},
        {'usages': ['invalid']},
        {'usages': [123]},
        {'usages': {}},
        {},
        'invalid',
    ],
)
def test_profile_rejects_invalid_or_unrelated_eku(eku):
    profile = CertificateProfileModel.objects.get(unique_name='traceability_credential')
    definition = profile.profile
    definition['ext']['extended_key_usage'] = eku
    with pytest.raises(ValidationError):
        Service._validate_profile_security_semantics(definition)
