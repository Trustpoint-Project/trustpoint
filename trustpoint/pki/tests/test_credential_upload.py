# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Credential input parity and resource limits across forms and API adapters."""

import datetime
from io import BytesIO
from unittest.mock import Mock, patch

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, mldsa, rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from django.core.exceptions import ValidationError
from django.core.files.uploadedfile import SimpleUploadedFile
from rest_framework.exceptions import ValidationError as ApiValidationError
from trustpoint_core.serializer import CertificateCollectionSerializer, PrivateKeyLocation

from management.forms import TlsAddFileImportPkcs12Form, TlsAddFileImportSeparateFilesForm
from pki.forms.issuing_cas import IssuingCaAddFileImportPkcs12Form, IssuingCaAddFileImportSeparateFilesForm
from pki.forms.owner_credential import OwnerCredentialFileImportForm
from pki.rollover.import_ca import ImportCaRolloverForm
from pki.serializer.owner_credential import OwnerCredentialFileImportSerializer
from pki.services import credential_upload as uploads
from signer.forms import SignerAddFileImportPkcs12Form, SignerAddFileImportSeparateFilesForm


@pytest.fixture(scope='module', params=['rsa', 'ec', 'mldsa44', 'mldsa65', 'mldsa87'])
def private_key(request):
    """Generate real keys without relying on mocks of native deserializers."""
    if request.param == 'rsa':
        return rsa.generate_private_key(public_exponent=65537, key_size=2048)
    if request.param == 'ec':
        return ec.generate_private_key(ec.SECP256R1())
    return {
        'mldsa44': mldsa.MLDSA44PrivateKey,
        'mldsa65': mldsa.MLDSA65PrivateKey,
        'mldsa87': mldsa.MLDSA87PrivateKey,
    }[request.param].generate()


def _load_key(client, data, password):
    upload = SimpleUploadedFile('key.bin', data)
    if client == 'api':
        return OwnerCredentialFileImportSerializer()._parse_private_key(
            {
                'private_key_file': upload,
                'private_key_file_password': password,
            }
        )
    form_type = {
        'owner': OwnerCredentialFileImportForm,
        'ca': IssuingCaAddFileImportSeparateFilesForm,
        'signer': SignerAddFileImportSeparateFilesForm,
        'tls': TlsAddFileImportSeparateFilesForm,
    }[client]
    form = form_type(data={'private_key_file_password': password})
    form.cleaned_data = {'private_key_file': upload}
    result = form.clean_private_key_file()
    if client == 'tls':
        return form._parse_private_key(result, form._encode_private_key_password(password))
    return result


@pytest.mark.parametrize('client', ['owner', 'ca', 'signer', 'tls', 'api'])
@pytest.mark.parametrize('encoding', [serialization.Encoding.PEM, serialization.Encoding.DER])
@pytest.mark.parametrize('password', ['', 'pässphrase-秘密'])
def test_private_key_format_and_password_parity(private_key, client, encoding, password):
    """Every consumer accepts the same key formats and UTF-8 encrypted input."""
    encryption = serialization.BestAvailableEncryption(password.encode()) if password else serialization.NoEncryption()
    data = private_key.private_bytes(encoding, serialization.PrivateFormat.PKCS8, encryption)
    loaded = _load_key(client, data, password).as_crypto()
    assert loaded.public_key() == private_key.public_key()


@pytest.mark.parametrize('client', ['owner', 'ca', 'signer', 'tls', 'api'])
@pytest.mark.parametrize('password', ['', 'wrong-password'])
def test_wrong_key_password_remains_a_validation_error(private_key, client, password):
    """Password failures remain form errors or field-level DRF errors without exposing secrets."""
    data = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.BestAvailableEncryption(b'actual-secret'),
    )
    error_type = ApiValidationError if client == 'api' else ValidationError
    with pytest.raises(error_type) as failure:
        _load_key(client, data, password)
    assert 'actual-secret' not in str(failure.value)
    if client == 'api':
        assert 'private_key_file' in failure.value.detail


@pytest.fixture(scope='module')
def certificates():
    """Create a certificate collection and matching private key for real format tests."""
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.datetime.now(datetime.UTC)
    certs = []
    for name in ('first.example', 'second.example'):
        subject = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, name)])
        certs.append(
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=1))
            .sign(key, hashes.SHA256())
        )
    return key, certs


@pytest.mark.parametrize('encoding', [serialization.Encoding.PEM, serialization.Encoding.DER])
def test_certificate_parsing_parity(certificates, encoding):
    """API and form adapters parse the same certificate without relying on its filename."""
    _, certs = certificates
    data = certs[0].public_bytes(encoding)
    form = TlsAddFileImportSeparateFilesForm()
    form.cleaned_data = {'tls_certificate': SimpleUploadedFile('certificate.bin', data)}
    from_form = form.clean_tls_certificate().as_crypto()
    from_api = (
        OwnerCredentialFileImportSerializer()
        ._parse_certificate(
            {
                'certificate': SimpleUploadedFile('certificate.bin', data),
            }
        )
        .as_crypto()
    )
    assert from_form == from_api == certs[0]


@pytest.mark.parametrize('encoding', ['pem', 'pkcs7-pem', 'pkcs7-der'])
def test_chain_format_order_and_optional_parity(certificates, encoding):
    """Each chain consumer retains supported formats, certificate order and optional uploads."""
    _, certs = certificates
    collection = CertificateCollectionSerializer(certs)
    data = {
        'pem': b''.join(cert.public_bytes(serialization.Encoding.PEM) for cert in certs),
        'pkcs7-pem': collection.as_pkcs7_pem(),
        'pkcs7-der': collection.as_pkcs7_der(),
    }[encoding]
    for form_type, field, method in [
        (OwnerCredentialFileImportForm, 'certificate_chain', 'clean_certificate_chain'),
        (IssuingCaAddFileImportSeparateFilesForm, 'ca_certificate_chain', 'clean_ca_certificate_chain'),
        (SignerAddFileImportSeparateFilesForm, 'signer_certificate_chain', 'clean_signer_certificate_chain'),
        (TlsAddFileImportSeparateFilesForm, 'tls_certificate_chain', 'clean_tls_certificate_chain'),
    ]:
        form = form_type()
        form.cleaned_data = {field: SimpleUploadedFile('chain.bin', data)}
        assert getattr(form, method)().as_crypto() == certs
        form.cleaned_data = {}
        assert getattr(form, method)() is None
    api = OwnerCredentialFileImportSerializer()
    assert api._parse_chain({'certificate_chain': SimpleUploadedFile('chain.bin', data)}).as_crypto() == certs
    assert api._parse_chain({}) is None


@pytest.mark.parametrize('password', ['', 'pässphrase-秘密'])
def test_pkcs12_extraction_and_signer_blank_password(certificates, password):
    """PKCS#12 extraction retains key, leaf and chain; blank signer passwords mean no password."""
    key, certs = certificates
    encryption = serialization.BestAvailableEncryption(password.encode()) if password else serialization.NoEncryption()
    data = pkcs12.serialize_key_and_certificates(b'credential', key, certs[0], [certs[1]], encryption)
    form = SignerAddFileImportPkcs12Form()
    raw, encoded = form._validate_pkcs12_file(
        {
            'pkcs12_file': SimpleUploadedFile('credential.p12', data),
            'pkcs12_password': password,
        }
    )
    with patch('signer.forms.get_private_key_location_from_config', return_value=PrivateKeyLocation.SOFTWARE):
        parsed = form._process_pkcs12_file(raw, encoded, 'uploaded')
    assert parsed.private_key.public_key() == key.public_key()
    assert parsed.certificate == certs[0]
    assert parsed.additional_certificates == [certs[1]]
    with pytest.raises(uploads.CredentialUploadError) as failure:
        uploads.parse_pkcs12(data, b'wrong-password')
    assert failure.value.code == uploads.CredentialUploadErrorCode.MALFORMED


LIMITS = [
    (uploads.CredentialFileKind.PRIVATE_KEY, uploads.MAX_PRIVATE_KEY_UPLOAD_BYTES),
    (uploads.CredentialFileKind.CERTIFICATE, uploads.MAX_CERTIFICATE_UPLOAD_BYTES),
    (uploads.CredentialFileKind.CHAIN, uploads.MAX_CERTIFICATE_CHAIN_UPLOAD_BYTES),
    (uploads.CredentialFileKind.PKCS12, uploads.MAX_PKCS12_UPLOAD_BYTES),
]


@pytest.mark.parametrize(('kind', 'limit'), LIMITS)
def test_declared_oversize_does_not_read(kind, limit):
    """Reject known oversized files without consuming their streams."""
    upload = Mock(size=limit + 1)
    with pytest.raises(uploads.CredentialUploadError) as failure:
        uploads.read_credential_upload(upload, kind=kind)
    assert failure.value.code == uploads.CredentialUploadErrorCode.TOO_LARGE
    upload.read.assert_not_called()


@pytest.mark.parametrize(('kind', 'limit'), LIMITS)
@pytest.mark.parametrize('declared_size', [None, 1])
def test_actual_size_is_bounded_even_with_false_metadata(kind, limit, declared_size):
    """Metadata cannot bypass limits, and the reader stops after detecting the first excess byte."""
    upload = BytesIO(b'x' * (limit + 100))
    if declared_size is not None:
        upload.size = declared_size
    with pytest.raises(uploads.CredentialUploadError) as failure:
        uploads.read_credential_upload(upload, kind=kind)
    assert failure.value.code == uploads.CredentialUploadErrorCode.TOO_LARGE
    assert upload.tell() == limit + 1


@pytest.mark.parametrize(('kind', 'limit'), LIMITS)
def test_exact_size_limit_is_accepted(kind, limit):
    """A file exactly at the configured limit is not rejected as oversized."""
    assert len(uploads.read_credential_upload(BytesIO(b'x' * limit), kind=kind)) == limit


@pytest.mark.parametrize('value', [None, '', b''])
def test_absent_passwords_are_normalized(value):
    """Blank text and binary passwords share the optional-password semantics."""
    assert uploads.encode_upload_password(value) is None


@pytest.mark.parametrize('value', ['\ud800', object(), ['invalid']])
def test_unencodable_password_is_controlled(value):
    """Malformed passwords are reported before reaching native parsers."""
    with pytest.raises(uploads.CredentialUploadError) as failure:
        uploads.encode_upload_password(value)
    assert failure.value.code == uploads.CredentialUploadErrorCode.INVALID_PASSWORD


@pytest.mark.parametrize(
    ('field', 'method', 'limit'),
    [
        ('private_key_file', '_parse_private_key', uploads.MAX_PRIVATE_KEY_UPLOAD_BYTES),
        ('certificate', '_parse_certificate', uploads.MAX_CERTIFICATE_UPLOAD_BYTES),
        ('certificate_chain', '_parse_chain', uploads.MAX_CERTIFICATE_CHAIN_UPLOAD_BYTES),
    ],
)
def test_api_oversize_errors_stay_on_the_uploaded_field(field, method, limit):
    """New API limits retain DRF field errors instead of failing during credential creation."""
    upload = SimpleUploadedFile('oversized.bin', b'x' * (limit + 1))
    upload.size = 1
    with pytest.raises(ApiValidationError) as failure:
        getattr(OwnerCredentialFileImportSerializer(), method)({field: upload})
    assert field in failure.value.detail
    assert 'too large' in str(failure.value)


@pytest.mark.parametrize(
    'form_type',
    [
        IssuingCaAddFileImportPkcs12Form,
        TlsAddFileImportPkcs12Form,
        SignerAddFileImportPkcs12Form,
        ImportCaRolloverForm,
    ],
)
def test_pkcs12_limits_apply_before_import_or_save(form_type):
    """All PKCS#12 flows, including rollover, reject oversized actual content before persistence."""
    upload = SimpleUploadedFile('oversized.p12', b'x' * (uploads.MAX_PKCS12_UPLOAD_BYTES + 1))
    upload.size = 1
    form = form_type()
    data = {'pkcs12_file': upload, 'pkcs12_password': ''}
    with pytest.raises(ValidationError, match='too large'):
        if form_type is IssuingCaAddFileImportPkcs12Form:
            form._read_and_encode_pkcs12_file(data)
        elif form_type is TlsAddFileImportPkcs12Form:
            form._read_pkcs12_file(data)
        elif form_type is SignerAddFileImportPkcs12Form:
            form._validate_pkcs12_file(data)
        else:
            form.cleaned_data = data
            form.clean()
