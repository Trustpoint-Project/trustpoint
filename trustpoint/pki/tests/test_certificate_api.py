# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Public certificate detail and download behavior through the REST API."""

import io
import ipaddress
import tarfile
import zipfile
from datetime import timedelta

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs7
from django.urls import reverse
from django.utils import timezone
from rest_framework.test import APIClient

from pki.models.certificate import CertificateModel, RevokedCertificateModel
from users.models import TrustpointUser


@pytest.fixture
def api():
    """Use the same authenticated access as the existing certificate API."""
    user = TrustpointUser.objects.create_user(username='certificate-reader', password='test-password')
    client = APIClient()
    client.force_authenticate(user)
    return client


@pytest.fixture
def leaf(issuing_ca_instance):
    """A real certificate with structured and unrecognized extensions, signed by a known CA."""
    now = timezone.now()
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    cert = (
        x509.CertificateBuilder()
        .subject_name(
            x509.Name(
                [
                    x509.RelativeDistinguishedName([x509.NameAttribute(x509.NameOID.COMMON_NAME, 'shared-name')]),
                    x509.RelativeDistinguishedName(
                        [
                            x509.NameAttribute(x509.NameOID.ORGANIZATIONAL_UNIT_NAME, 'One'),
                            x509.NameAttribute(x509.NameOID.ORGANIZATIONAL_UNIT_NAME, 'Two'),
                        ]
                    ),
                ]
            )
        )
        .issuer_name(issuing_ca_instance['cert'].subject)
        .public_key(key.public_key())
        .serial_number(2**120 + 17)
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.DNSName('example.test'),
                    x509.IPAddress(ipaddress.ip_address('192.0.2.1')),
                    x509.UniformResourceIdentifier('urn:test'),
                    x509.RFC822Name('user@example.test'),
                ]
            ),
            critical=False,
        )
        .add_extension(x509.ExtendedKeyUsage([x509.ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
        .add_extension(x509.UnrecognizedExtension(x509.ObjectIdentifier('1.2.3.4.5'), b'\x0c\x04test'), critical=False)
        .sign(issuing_ca_instance['priv_key'], hashes.SHA256())
    )
    return CertificateModel.save_certificate(cert)


def parse_certificates(content, file_format):
    """Parse downloaded bytes independently of the production serializers."""
    return {
        'pem': x509.load_pem_x509_certificates,
        'der': lambda data: [x509.load_der_x509_certificate(data)],
        'pkcs7_pem': pkcs7.load_pem_pkcs7_certificates,
        'pkcs7_der': pkcs7.load_der_pkcs7_certificates,
    }[file_format](content)


def test_detail_contains_full_public_certificate(api, leaf, issuing_ca_instance):
    """Details preserve certificate identity, name groupings, and extension information."""
    response = api.get(f'/api/certificates/{leaf.pk}/')
    assert response.status_code == 200, response.data
    data = response.data
    assert data['serial_number'] == f'{2**120 + 17:X}'
    assert data['sha256_fingerprint'] == leaf.sha256_fingerprint
    assert data['certificate_status'] == 'OK'
    assert data['issuer_certificate'] == issuing_ca_instance['issuing_ca'].ca_certificate_model.pk
    assert data['issued_certificate_count'] == 0
    root = issuing_ca_instance['issuing_ca'].ca_certificate_model
    assert api.get(f'/api/certificates/{root.pk}/').data['issued_certificate_count'] == 1
    assert data['is_ca'] is False
    assert data['spki_key_size'] == 2048
    assert data['revocation'] is None
    assert data['cert_pem'] == leaf.cert_pem
    assert 'PRIVATE KEY' not in str(data)
    unit_names = [attribute for attribute in data['subject'] if attribute['oid'] == '2.5.4.11']
    assert {attribute['value'] for attribute in unit_names} == {'One', 'Two'}
    assert len({attribute['rdn'] for attribute in unit_names}) == 1
    extensions = {item['oid']: item for item in data['extensions']}
    assert extensions['2.5.29.19']['value'] == {'ca': False, 'path_length': None}
    assert extensions['2.5.29.15']['value']['encipher_only'] is None
    assert extensions['1.2.3.4.5']['der_hex'] == '0C0474657374'
    assert {'type': 'IPAddress', 'value': '192.0.2.1'} in extensions['2.5.29.17']['value']


def test_list_adds_summary_and_preserves_search(api, leaf):
    """Inventory reads include status/expiry without copying full certificate contents into each row."""
    response = api.get('/api/certificates/', {'search': 'shared-name'})
    assert response.status_code == 200
    data = response.data['results'] if isinstance(response.data, dict) else response.data
    row = next(item for item in data if item['id'] == leaf.pk)
    assert row['common_name'] == 'shared-name'
    assert row['serial_number'] == leaf.serial_number
    assert row['certificate_status'] == 'OK'
    assert 'cert_pem' not in row
    assert 'not_valid_after' in row


def test_revocation_details(api, leaf, issuing_ca_instance):
    """The current certificate status and revocation record agree."""
    ca = issuing_ca_instance['issuing_ca']
    RevokedCertificateModel.objects.create(certificate=leaf, ca=ca, revocation_reason='keyCompromise')
    data = api.get(f'/api/certificates/{leaf.pk}/').data
    assert data['certificate_status'] == 'REV'
    assert data['revocation']['revocation_reason'] == 'keyCompromise'
    assert data['revocation']['ca'] == ca.pk
    assert data['revocation']['revoked_at']


@pytest.mark.parametrize('file_format', ['pem', 'der', 'pkcs7_pem', 'pkcs7_der'])
def test_single_download_all_formats(api, leaf, file_format):
    """Every format round-trips to the same certificate and has an attachment filename."""
    response = api.get(f'/api/certificates/{leaf.pk}/download/', {'file_format': file_format})
    assert response.status_code == 200
    assert parse_certificates(response.content, file_format)[0].serial_number == 2**120 + 17
    assert f'shared-name-{leaf.pk}' in response['Content-Disposition']


@pytest.mark.parametrize('file_format', ['pem', 'pkcs7_pem', 'pkcs7_der'])
def test_download_with_issuer_chain(api, leaf, issuing_ca_instance, file_format):
    """A single PEM/PKCS#7 file can contain the leaf and its known issuer chain."""
    root = issuing_ca_instance['issuing_ca'].ca_certificate_model
    response = api.get(f'/api/certificates/{leaf.pk}/download/', {'file_format': file_format, 'include_chain': 'true'})
    assert response.status_code == 200, getattr(response, 'data', response.content)
    downloaded = parse_certificates(response.content, file_format)
    assert {cert.serial_number for cert in downloaded} == {2**120 + 17, int(root.serial_number, 16)}
    assert api.get(f'/api/certificates/{leaf.pk}/').data['certificate_chain'] == [root.pk]


def test_der_chain_is_rejected(api, leaf):
    """DER files must never silently concatenate multiple certificates."""
    response = api.get(f'/api/certificates/{leaf.pk}/download/', {'file_format': 'der', 'include_chain': 'true'})
    assert response.status_code == 400


@pytest.mark.parametrize('archive_format', ['zip', 'tar_gz'])
@pytest.mark.parametrize('file_format', ['pem', 'der', 'pkcs7_pem', 'pkcs7_der'])
def test_archive_formats_and_chain_deduplication(api, leaf, issuing_ca_instance, archive_format, file_format):
    """Archives contain valid individual files, with shared issuers included once."""
    root = issuing_ca_instance['issuing_ca'].ca_certificate_model
    response = api.post(
        '/api/certificates/download/',
        {
            'certificate_ids': [leaf.pk, root.pk, leaf.pk],
            'file_format': file_format,
            'archive_format': archive_format,
            'include_chain': True,
        },
        format='json',
    )
    assert response.status_code == 200, getattr(response, 'data', response.content)
    contents = io.BytesIO(response.content)
    if archive_format == 'zip':
        with zipfile.ZipFile(contents) as archive:
            assert len(archive.namelist()) == 2
            files = [archive.read(name) for name in archive.namelist()]
    else:
        with tarfile.open(fileobj=contents, mode='r:gz') as archive:
            assert len(archive.getnames()) == 2
            files = [archive.extractfile(member).read() for member in archive.getmembers()]
    assert {parse_certificates(file, file_format)[0].serial_number for file in files} == {
        2**120 + 17,
        int(root.serial_number, 16),
    }


@pytest.mark.parametrize(
    'payload',
    [
        {},
        {'certificate_ids': []},
        {'certificate_ids': ['invalid']},
        {'certificate_ids': [-1]},
        {'certificate_ids': [1], 'file_format': 'invalid'},
        {'certificate_ids': [1], 'archive_format': 'invalid'},
    ],
)
def test_invalid_archive_selection(api, payload):
    """Invalid input produces a validation response rather than a partial archive."""
    assert api.post('/api/certificates/download/', payload, format='json').status_code == 400


def test_missing_certificate_and_invalid_query(api, leaf):
    """Missing IDs produce 404 and unsupported download options produce 400."""
    assert api.get('/api/certificates/999999/').status_code == 404
    assert api.get('/api/certificates/999999/download/').status_code == 404
    assert api.get(f'/api/certificates/{leaf.pk}/download/', {'file_format': 'invalid'}).status_code == 400
    assert api.get(f'/api/certificates/{leaf.pk}/download/', {'include_chain': 'invalid'}).status_code == 400
    assert (
        api.post('/api/certificates/download/', {'certificate_ids': [leaf.pk, 999999]}, format='json').status_code
        == 404
    )


def test_downloads_require_authentication(leaf):
    """The new reads/downloads use the existing authenticated certificate access policy."""
    client = APIClient()
    for url in (f'/api/certificates/{leaf.pk}/', f'/api/certificates/{leaf.pk}/download/'):
        assert client.get(url).status_code in (401, 403)
    assert client.post('/api/certificates/download/', {'certificate_ids': [leaf.pk]}, format='json').status_code in (
        401,
        403,
    )


def test_existing_write_validation_is_preserved(api, leaf):
    """Richer read schemas do not bypass the existing write field constraints."""
    response = api.patch(f'/api/certificates/{leaf.pk}/', {'common_name': 'x' * 257}, format='json')
    assert response.status_code == 400
    assert 'common_name' in response.data
    assert CertificateModel.objects.get(pk=leaf.pk).common_name == 'shared-name'


def test_certificate_openapi_contract():
    """Details and both download actions have usable generated schemas."""
    from django.urls import include, path
    from drf_spectacular.generators import SchemaGenerator

    schema = SchemaGenerator(patterns=[path('api/', include('pki.api_urls'))]).get_schema(public=True)
    paths = schema['paths']
    assert 'get' in paths['/api/certificates/{id}/download/']
    assert 'post' in paths['/api/certificates/download/']
    assert 'CertificateDetail' in schema['components']['schemas']
    assert reverse('pki:certificate-download', kwargs={'pk': 12}) == '/pki/certificates/download/12'


def test_duplicate_common_names_have_distinct_archive_files(api, leaf, issuing_ca_instance):
    """Certificates sharing a common name cannot overwrite each other in an archive."""
    original = leaf.get_certificate_serializer().as_crypto()
    second = CertificateModel.save_certificate(
        x509.CertificateBuilder()
        .subject_name(original.subject)
        .issuer_name(original.issuer)
        .public_key(original.public_key())
        .serial_number(42)
        .not_valid_before(original.not_valid_before_utc)
        .not_valid_after(original.not_valid_after_utc)
        .sign(issuing_ca_instance['priv_key'], hashes.SHA256())
    )
    response = api.post('/api/certificates/download/', {'certificate_ids': [leaf.pk, second.pk]}, format='json')
    assert response.status_code == 200
    with zipfile.ZipFile(io.BytesIO(response.content)) as archive:
        assert set(archive.namelist()) == {f'shared-name-{leaf.pk}.pem', f'shared-name-{second.pk}.pem'}
        assert {x509.load_pem_x509_certificate(archive.read(name)).serial_number for name in archive.namelist()} == {
            2**120 + 17,
            42,
        }


def test_unsafe_certificate_names_are_safe_attachments(api, leaf):
    """Untrusted names cannot insert headers or archive paths."""
    CertificateModel.objects.filter(pk=leaf.pk).update(common_name='../..//\r\n"unsafe')
    response = api.get(f'/api/certificates/{leaf.pk}/download/')
    assert response.status_code == 200
    assert '\r' not in response['Content-Disposition']
    assert '\n' not in response['Content-Disposition']
    response = api.post('/api/certificates/download/', {'certificate_ids': [leaf.pk]}, format='json')
    with zipfile.ZipFile(io.BytesIO(response.content)) as archive:
        assert len(archive.namelist()) == 1
        assert '/' not in archive.namelist()[0]
        assert not archive.namelist()[0].startswith('.')


def test_cyclic_issuer_chain_returns_validation_error(api, leaf, issuing_ca_instance):
    """Malformed hierarchy data must not make downloads recurse forever."""
    root = issuing_ca_instance['issuing_ca'].ca_certificate_model
    CertificateModel.objects.filter(pk=root.pk).update(issuer_id=leaf)
    response = api.get(f'/api/certificates/{leaf.pk}/download/', {'include_chain': 'true'})
    assert response.status_code == 400
    assert api.get(f'/api/certificates/{leaf.pk}/').status_code == 400


def test_root_der_download_with_chain_does_not_duplicate_root(api, issuing_ca_instance):
    """A root certificate alone remains a valid single DER certificate."""
    root = issuing_ca_instance['issuing_ca'].ca_certificate_model
    response = api.get(f'/api/certificates/{root.pk}/download/', {'file_format': 'der', 'include_chain': 'true'})
    assert response.status_code == 200
    assert x509.load_der_x509_certificate(response.content).serial_number == int(root.serial_number, 16)
    data = api.get(f'/api/certificates/{root.pk}/').data
    assert data['is_root_ca'] is True
    assert data['certificate_chain'] == []


def test_associated_device_and_profile_metadata(api, tls_client_credential_instance):
    """The UI's device/profile association is available without exposing private credentials."""
    issued = tls_client_credential_instance['issued_credential']
    response = api.get(f'/api/certificates/{issued.credential.certificate.pk}/')
    assert response.status_code == 200, response.data
    data = response.data['issued_credentials']
    assert len(data) == 1
    assert data[0]['id'] == issued.pk
    assert data[0]['device'] == issued.device_id
    assert data[0]['device_name'] == issued.device.common_name
    assert data[0]['issued_using_cert_profile'] == issued.issued_using_cert_profile
    assert 'private_key' not in data[0]
