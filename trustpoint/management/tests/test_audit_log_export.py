# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Signed audit snapshot and independent verification regression tests."""

import copy
import json
import subprocess
import sys
from io import BytesIO
from pathlib import Path
from typing import Any
from zipfile import ZipFile

import pytest
from cryptography import x509
from jwt.api_jws import PyJWS
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission
from django.core.exceptions import ValidationError
from django.core.management import call_command
from django.test import Client
from django.urls import reverse

from management.models import AuditLog, LoggingConfig
from management.models.traceability import TraceabilityCredentialModel
from management.services import audit_log_export
from management.services.traceability_signing import TraceabilityCredentialService
from util.audit_log_export import base64url_decode, base64url_encode, encode_json, load_json, verify_export

pytestmark = pytest.mark.django_db


@pytest.fixture(params=[TraceabilityCredentialModel.Curve.SECP256R1, TraceabilityCredentialModel.Curve.SECP384R1])
def credential(settings: Any, request: pytest.FixtureRequest) -> TraceabilityCredentialModel:
    """Create a software-backed signing identity and two audit events."""
    settings.DEVELOPMENT_ENV = True
    settings.TRUSTPOINT_AUTO_CONFIGURE_LOCAL_SOFTWARE_BACKEND = True
    settings.TRUSTPOINT_IS_OPERATIONAL = True
    settings.DOCKER_CONTAINER = False
    call_command('create_default_cert_profiles')
    credential = TraceabilityCredentialService.create(
        name='audit-export',
        curve=request.param,
    )
    for operation in (AuditLog.OperationType.CREDENTIAL_ISSUED, AuditLog.OperationType.CREDENTIAL_REVOKED):
        AuditLog.create_entry(operation, credential, 'Export target', details={'message': 'évidence'})
    return credential


@pytest.fixture
def document(credential: TraceabilityCredentialModel) -> dict[str, Any]:
    """Sign a snapshot of the seeded entries."""
    return audit_log_export.create_signed_export(
        AuditLog.objects.filter(target_display='Export target'), credential, {}
    )


@pytest.fixture
def trusted_certificate(credential: TraceabilityCredentialModel) -> bytes:
    """Obtain the pinned certificate independently of the downloaded document."""
    assert credential.current_generation is not None
    return credential.current_generation.credential.get_certificate_serializer().as_pem()


def test_export_verifies_offline_after_rotation_and_retirement(credential, document, tmp_path):
    assert credential.current_generation is not None
    trusted = credential.current_generation.credential.get_certificate_serializer().as_pem()
    TraceabilityCredentialService.rotate(traceability_credential=credential)
    TraceabilityCredentialService.retire(credential)
    payload = verify_export(document, trusted)
    assert payload['entry_count'] == 2
    export_file, trusted_file = tmp_path / 'audit.json', tmp_path / 'trusted.pem'
    export_file.write_text(json.dumps(document))
    trusted_file.write_bytes(trusted)
    verifier = Path(__file__).parents[2] / 'util' / 'audit_log_export.py'
    result = subprocess.run(
        [sys.executable, '-I', str(verifier), str(export_file), '--trusted-certificate', str(trusted_file)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert 'Verified 2 entries' in result.stdout
    altered_payload = load_json(base64url_decode(document['payload']))
    altered_payload['entries'].reverse()
    document['payload'] = base64url_encode(encode_json(altered_payload))
    export_file.write_text(json.dumps(document))
    failed = subprocess.run(
        [sys.executable, '-I', str(verifier), str(export_file), '--trusted-certificate', str(trusted_file)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert failed.returncode == 1
    assert 'Verification failed' in failed.stderr


@pytest.mark.parametrize('change', ['edit', 'remove', 'reorder', 'context', 'range', 'signer'])
def test_tampering_invalidates_export(document, trusted_certificate, change):
    altered = copy.deepcopy(document)
    payload = load_json(base64url_decode(altered['payload']))
    if change == 'edit':
        payload['entries'][0]['details']['message'] = 'tampered'
    elif change == 'remove':
        payload['entries'].pop()
        payload['entry_count'] -= 1
    elif change == 'reorder':
        payload['entries'].reverse()
    elif change == 'context':
        payload['context'] = 'other-context'
    elif change == 'range':
        payload['filters'] = {'operation_type': 'OTHER'}
    else:
        payload['signer']['generation_number'] += 1
    altered['payload'] = base64url_encode(encode_json(payload))
    with pytest.raises(ValueError, match='Invalid audit export'):
        verify_export(altered, trusted_certificate)


def test_embedded_certificate_does_not_establish_trust(credential, document):
    new_generation = TraceabilityCredentialService.rotate(traceability_credential=credential)
    with pytest.raises(ValueError, match='untrusted signing certificate'):
        verify_export(document, new_generation.credential.get_certificate_serializer().as_pem())


def test_export_interoperates_with_pyjwt(credential, document, trusted_certificate):
    """An independent JOSE library verifies the export and produces exports we can verify."""
    certificate = x509.load_pem_x509_certificate(trusted_certificate)
    header = load_json(base64url_decode(document['protected']))
    algorithm = header['alg']
    assert algorithm in {'ES256', 'ES384'}
    expected_size = 64 if algorithm == 'ES256' else 96
    assert len(base64url_decode(document['signature'])) == expected_size
    compact = '.'.join(document[name] for name in ('protected', 'payload', 'signature'))
    verified = PyJWS().decode(compact, key=certificate.public_key(), algorithms=[algorithm])
    assert load_json(verified) == verify_export(document, trusted_certificate)

    assert credential.current_generation is not None
    independent = PyJWS().encode(
        verified,
        key=credential.current_generation.credential.get_private_key(),
        algorithm=algorithm,
        headers={**header, 'typ': None},
        sort_headers=False,
    )
    protected, payload, signature = independent.split('.')
    assert verify_export(
        {'protected': protected, 'payload': payload, 'signature': signature},
        trusted_certificate,
    ) == load_json(verified)


@pytest.mark.parametrize('change', ['alg', 'crit', 'b64', 'padding', 'length', 'unprotected'])
def test_invalid_jws_parameters_are_rejected(credential, document, trusted_certificate, change):
    altered = copy.deepcopy(document)
    header = load_json(base64url_decode(altered['protected']))
    signing_algorithm = header['alg']
    if change == 'alg':
        header['alg'] = 'none'
    elif change == 'crit':
        header.update(crit=['unknown'], unknown=True)
    elif change == 'b64':
        header.update(b64=False, crit=['b64'])
    elif change == 'padding':
        altered['payload'] += '='
    elif change == 'length':
        altered['signature'] = base64url_encode(base64url_decode(altered['signature'])[:-1])
    else:
        altered['header'] = {'alg': 'none'}
    if change in {'alg', 'crit', 'b64'}:
        altered['protected'] = base64url_encode(encode_json(header))
        assert credential.current_generation is not None
        # Keep the EC signature valid so this test checks header policy rather than tampering.
        signature = (
            PyJWS()
            .get_algorithm_by_name(signing_algorithm)
            .sign(
                f'{altered["protected"]}.{altered["payload"]}'.encode('ascii'),
                credential.current_generation.credential.get_private_key(),
            )
        )
        altered['signature'] = base64url_encode(signature)
    with pytest.raises(ValueError, match='Invalid audit export'):
        verify_export(altered, trusted_certificate)


@pytest.mark.parametrize('value', ['Zg=', 'Zg\n', 'Zg+', 'Zg/', 'Z', 'Zh'])
def test_base64url_rejects_invalid_encodings(value):
    with pytest.raises(ValueError):
        base64url_decode(value)


@pytest.mark.parametrize(
    'value',
    [
        '{"alg":"ES256","alg":"ES384"}',
        '{"value":NaN}',
        '{"value":Infinity}',
        '{"alg":"ES256"}'.encode('utf-16'),
    ],
)
def test_json_rejects_duplicate_members_and_non_json_numbers(value):
    with pytest.raises(ValueError):
        load_json(value)


def test_snapshot_excludes_its_own_crypto_audit_events(credential):
    LoggingConfig.objects.create(crypto_backend_audit_enabled=True)
    before = list(AuditLog.objects.order_by('timestamp', 'pk').values_list('pk', flat=True))
    document = audit_log_export.create_signed_export(AuditLog.objects.all(), credential, {})
    assert [entry['id'] for entry in load_json(base64url_decode(document['payload']))['entries']] == before
    assert AuditLog.objects.filter(operation_type=AuditLog.OperationType.CRYPTO_SIGN).exists()
    assert AuditLog.objects.count() > len(before)


def test_empty_snapshot_is_verifiable(credential, trusted_certificate):
    document = audit_log_export.create_signed_export(AuditLog.objects.none(), credential, {})
    assert verify_export(document, trusted_certificate)['entry_count'] == 0


def test_export_limit_and_retired_credential_reject_download(credential, monkeypatch):
    monkeypatch.setattr(audit_log_export, 'MAX_EXPORT_ENTRIES', 1)
    with pytest.raises(ValidationError, match='Narrow the audit log filters'):
        audit_log_export.create_signed_export(AuditLog.objects.all(), credential, {})
    TraceabilityCredentialService.retire(credential)
    with pytest.raises(ValidationError, match='not currently usable'):
        audit_log_export.create_signed_export(AuditLog.objects.none(), credential, {})


def test_export_view_preserves_filters_and_checks_permissions(credential, trusted_certificate):
    user = get_user_model().objects.create_user(username='audit-reader')
    user.user_permissions.add(Permission.objects.get(codename='view_audit_log'))
    client = Client()
    client.force_login(user)
    url = reverse('management:audit-log-export') + '?operation_type=CREDENTIAL_ISSUED&page=4'
    assert client.post(url, {'credential': credential.pk}).status_code == 403
    user.user_permissions.add(Permission.objects.get(codename='manage_traceability_credentials'))
    response = client.post(url, {'credential': credential.pk})
    assert response.status_code == 200
    document = response.json()
    payload = verify_export(document, trusted_certificate)
    assert payload['entry_count'] == 1
    assert payload['filters'] == {'operation_type': 'CREDENTIAL_ISSUED'}
    assert response['Content-Type'] == 'application/jose+json'
    assert response['Cache-Control'] == 'no-store'
    bad = client.post(
        reverse('management:audit-log-export') + '?timestamp_after=invalid', {'credential': credential.pk}
    )
    assert bad.status_code == 200
    assert 'Invalid audit log filters' in bad.content.decode()


def test_signing_failure_does_not_download_unsigned_data(credential, monkeypatch):
    user = get_user_model().objects.create_superuser(username='export-admin', password='test-password')
    client = Client()
    client.force_login(user)

    def fail_signing(**kwargs):
        raise RuntimeError('backend signing unavailable')

    monkeypatch.setattr(TraceabilityCredentialService, 'sign', fail_signing)
    response = client.post(reverse('management:audit-log-export'), {'credential': credential.pk})
    assert response.status_code == 200
    assert 'Content-Disposition' not in response
    assert 'Could not sign the export' in response.content.decode()
    assert 'backend signing unavailable' not in response.content.decode()


@pytest.mark.parametrize('include_certificate', [False, True])
def test_download_and_exact_signing_certificate(credential, trusted_certificate, monkeypatch, include_certificate):
    user = get_user_model().objects.create_superuser(username='format-admin', password='test-password')
    client = Client()
    client.force_login(user)
    url = reverse('management:audit-log-export')
    page = client.get(url)
    assert page.status_code == 200
    assert 'name="format"' not in page.content.decode()
    assert 'name="include_certificate"' in page.content.decode()

    def sign_then_rotate(*args):
        document = audit_log_export.create_signed_export(*args)
        TraceabilityCredentialService.rotate(traceability_credential=credential)
        return document

    monkeypatch.setattr('management.views.audit_log.create_signed_export', sign_then_rotate)
    response = client.post(
        url,
        {
            'credential': credential.pk,
            'include_certificate': include_certificate,
        },
    )
    assert response.status_code == 200
    assert response['Cache-Control'] == 'no-store'
    filename = 'trustpoint-audit-log.json'
    if include_certificate:
        assert response['Content-Type'] == 'application/zip'
        assert response['Content-Disposition'] == 'attachment; filename="trustpoint-audit-log.zip"'
        with ZipFile(BytesIO(response.content)) as archive:
            assert set(archive.namelist()) == {filename, 'signing-certificate.pem'}
            assert archive.read('signing-certificate.pem') == trusted_certificate
            content = archive.read(filename)
    else:
        assert response['Content-Type'] == 'application/jose+json'
        assert response['Content-Disposition'] == f'attachment; filename="{filename}"'
        content = response.content
    document = load_json(content)
    assert set(document) == {'payload', 'protected', 'signature'}
    assert verify_export(document, trusted_certificate)['entry_count'] >= 2
