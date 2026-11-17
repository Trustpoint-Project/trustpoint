# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Checkpoint-anchored audit evidence export and offline verification tests."""

from __future__ import annotations

import copy
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission
from django.core.exceptions import ValidationError
from django.core.management import call_command
from django.db.models import QuerySet
from django.test import Client
from django.urls import reverse

from management.models import AuditLog
from management.models.audit_signing import AuditLogCheckpoint, AuditSigningConfig
from management.models.traceability import TraceabilityCredentialModel
from management.services import audit_log_export
from management.services.audit_log_export import create_evidence_export
from management.services.audit_signing import create_checkpoint
from management.services.traceability_signing import TraceabilityCredentialService
from util.audit_log_export import EVIDENCE_FORMAT, _entry_hash, verify_evidence_package

pytestmark = pytest.mark.django_db


@pytest.fixture
def credential(settings: Any, traceability_management_ca) -> TraceabilityCredentialModel:
    settings.DEVELOPMENT_ENV = True
    settings.TRUSTPOINT_AUTO_CONFIGURE_LOCAL_SOFTWARE_BACKEND = True
    settings.TRUSTPOINT_IS_OPERATIONAL = True
    settings.DOCKER_CONTAINER = False
    call_command('create_default_cert_profiles')
    credential = TraceabilityCredentialService.create(
        management_ca=traceability_management_ca,
        name='audit-export',
    )
    AuditLog.objects.all().delete()
    return credential


@pytest.fixture
def target():
    return get_user_model().objects.create_user(username='export-target')


def enable_signing(credential: TraceabilityCredentialModel, *, events: int = 100) -> None:
    config = AuditSigningConfig.get()
    config.enabled = True
    config.traceability_credential = credential
    config.checkpoint_event_interval = events
    config.checkpoint_time_interval_minutes = None
    config.full_clean()
    config.save()


def make_entry(target, operation: str = AuditLog.OperationType.CREDENTIAL_ISSUED):
    return AuditLog.create_entry(
        operation,
        target,
        'Export target',
        details={'message': 'évidence'},
    )


def trusted_certificate(credential: TraceabilityCredentialModel) -> bytes:
    assert credential.current_generation is not None
    return credential.current_generation.credential.get_certificate_serializer().as_pem()


def full_export_with_checkpoint(credential, target) -> tuple[dict[str, Any], bytes]:
    enable_signing(credential, events=100)
    make_entry(target)
    make_entry(target)
    create_checkpoint()
    return create_evidence_export(AuditLog.objects.all(), {}), trusted_certificate(credential)


def test_full_export_has_no_snapshot_signature_and_verifies(credential, target):
    document, trusted = full_export_with_checkpoint(credential, target)

    assert document['format'] == EVIDENCE_FORMAT
    assert document['snapshot_signature'] is None
    assert document['evidence']['scope'] == 'full'
    assert document['evidence']['complete_chain'] is True
    assert document['evidence']['entry_count'] == 2
    assert len(document['evidence']['checkpoints']) == 1
    assert set(document['evidence']['checkpoints'][0]) == {'payload', 'signature'}
    assert document['evidence']['checkpoints'][0]['payload']['checkpoint_number'] == 1
    assert len(document['evidence']['certificates']) == 1

    report = verify_evidence_package(document, [trusted])
    assert report['ok']
    assert report['entries_checked'] == 2
    assert report['checkpoints_checked'] == 1
    assert report['unsigned_entries'] == 0
    assert not report['findings']


@pytest.mark.parametrize('empty', [False, True])
def test_full_export_stops_at_signed_checkpoint_after_commit(
    credential, target, django_capture_on_commit_callbacks, *, empty: bool
):
    enable_signing(credential)
    entry = None if empty else make_entry(target)
    with django_capture_on_commit_callbacks(execute=True):
        checkpoint = create_checkpoint()
    assert checkpoint is not None
    assert AuditLog.objects.filter(operation_type=AuditLog.OperationType.AUDIT_CHECKPOINT_SIGNED).exists()
    make_entry(target)

    document = create_evidence_export(AuditLog.objects.all(), {})

    evidence = document['evidence']
    assert [row['id'] for row in evidence['entries']] == ([] if entry is None else [entry.pk])
    assert evidence['chain']['head_sequence'] == checkpoint.last_sequence
    assert evidence['chain']['head_hash'] == checkpoint.head_hash
    assert evidence['chain']['unsigned_entries'] == 0
    report = verify_evidence_package(document, [trusted_certificate(credential)])
    assert report['ok'], report['findings']


@pytest.mark.parametrize('empty', [False, True])
@pytest.mark.parametrize(
    'field',
    [
        'entry_count',
        'first_entry_id',
        'last_entry_id',
        'first_sequence',
        'last_sequence',
        'first_timestamp',
        'last_timestamp',
    ],
)
def test_full_export_rejects_incorrect_summary(
    credential: TraceabilityCredentialModel, target: Any, *, empty: bool, field: str
) -> None:
    """Reject summary changes even when all event hashes and checkpoint signatures remain valid."""
    enable_signing(credential)
    if not empty:
        make_entry(target)
    create_checkpoint()
    document = create_evidence_export(AuditLog.objects.all(), {})
    trusted = trusted_certificate(credential)
    assert verify_evidence_package(document, [trusted])['ok']
    if field == 'entry_count':
        document['evidence'][field] = 999
    else:
        document['evidence']['range'][field] = 'incorrect'

    report = verify_evidence_package(document, [trusted])

    assert not report['ok']
    assert 'PACKAGE_MISMATCH' in {finding['code'] for finding in report['findings']}


@pytest.mark.parametrize('scope', ['full', 'filtered'])
@pytest.mark.parametrize('write_after', ['head', 'checkpoint'])
def test_export_stays_consistent_when_events_arrive(
    credential: TraceabilityCredentialModel,
    target: Any,
    monkeypatch: pytest.MonkeyPatch,
    scope: str,
    write_after: str,
) -> None:
    """Keep one export boundary when writes arrive between its database reads."""
    enable_signing(credential)
    entry = make_entry(target)
    create_checkpoint()
    injected = False

    def append_and_sign() -> None:
        nonlocal injected
        if not injected:
            injected = True
            make_entry(target)
            create_checkpoint()

    original_first = QuerySet.first
    original_document = audit_log_export._checkpoint_document  # noqa: SLF001 - inject a write between export reads

    def first(queryset: QuerySet[AuditLog]) -> AuditLog | None:
        result = original_first(queryset)
        if queryset.model is AuditLog:
            append_and_sign()
        return result

    def checkpoint_document(checkpoint: Any) -> dict[str, Any]:
        append_and_sign()
        return original_document(checkpoint)

    if write_after == 'head':
        monkeypatch.setattr(QuerySet, 'first', first)
    else:
        monkeypatch.setattr(audit_log_export, '_checkpoint_document', checkpoint_document)
    filters = {'target_object_id': str(target.pk)} if scope == 'filtered' else {}
    document = create_evidence_export(AuditLog.objects.all(), filters)

    assert injected
    evidence = document['evidence']
    assert evidence['chain']['head_sequence'] == entry.sequence
    assert evidence['entry_count'] == 1
    assert len(evidence['checkpoints']) == 1
    report = verify_evidence_package(document, [trusted_certificate(credential)])
    assert report['ok'], report['findings']


@pytest.mark.parametrize('change', ['edit', 'remove', 'reorder', 'signature'])
def test_full_export_tampering_is_detected(credential, target, change):
    document, trusted = full_export_with_checkpoint(credential, target)
    altered = copy.deepcopy(document)
    if change == 'edit':
        altered['evidence']['entries'][0]['details']['message'] = 'tampered'
    elif change == 'remove':
        altered['evidence']['entries'].pop()
        altered['evidence']['chain']['head_sequence'] = altered['evidence']['entries'][-1]['sequence']
        altered['evidence']['chain']['head_hash'] = altered['evidence']['entries'][-1]['entry_hash']
    elif change == 'reorder':
        altered['evidence']['entries'].reverse()
    else:
        altered['evidence']['checkpoints'][0]['signature'] = 'AAAA'

    report = verify_evidence_package(altered, [trusted])
    assert not report['ok']


def test_untrusted_checkpoint_certificate_is_rejected(credential, target):
    document, _trusted = full_export_with_checkpoint(credential, target)
    new_generation = TraceabilityCredentialService.rotate(traceability_credential=credential)
    report = verify_evidence_package(
        document,
        [new_generation.credential.get_certificate_serializer().as_pem()],
    )
    assert not report['ok']
    assert 'UNTRUSTED_CERTIFICATE' in {finding['code'] for finding in report['findings']}


def test_full_export_rejects_checkpoint_newer_than_truncated_head(credential, target):
    enable_signing(credential)
    make_entry(target)
    second = make_entry(target)
    create_checkpoint()
    AuditLog.objects.filter(pk=second.pk).delete()

    with pytest.raises(ValidationError, match='may be truncated'):
        create_evidence_export(AuditLog.objects.all(), {})


def test_full_export_without_signing_fails_verification(credential, target):
    make_entry(target)
    document = create_evidence_export(AuditLog.objects.all(), {})

    assert document['snapshot_signature'] is None
    report = verify_evidence_package(document)
    assert not report['ok']
    codes = {finding['code'] for finding in report['findings']}
    assert codes == {'NO_SIGNED_CHECKPOINTS', 'UNSIGNED_EVENTS'}


def test_full_export_rejects_fabricated_tail_after_checkpoint(credential, target):
    """Events after the last signed checkpoint are unauthenticated and must fail verification."""
    document, trusted = full_export_with_checkpoint(credential, target)
    evidence = document['evidence']
    last = evidence['entries'][-1]
    forged = {
        **last,
        'id': last['id'] + 1,
        'sequence': last['sequence'] + 1,
        'previous_hash': last['entry_hash'],
        'target_display': 'Forged event',
    }
    forged['entry_hash'] = _entry_hash(forged)
    evidence['entries'].append(forged)
    evidence['entry_count'] += 1
    evidence['range']['last_entry_id'] = forged['id']
    evidence['range']['last_sequence'] = forged['sequence']
    evidence['chain']['head_sequence'] = forged['sequence']
    evidence['chain']['head_hash'] = forged['entry_hash']
    evidence['chain']['unsigned_entries'] += 1

    report = verify_evidence_package(document, [trusted])
    assert not report['ok']
    assert 'UNSIGNED_EVENTS' in {finding['code'] for finding in report['findings']}


def test_full_export_verifies_after_key_rotation(credential, target):
    enable_signing(credential)
    first_certificate = trusted_certificate(credential)
    make_entry(target)
    create_checkpoint()
    new_generation = TraceabilityCredentialService.rotate(traceability_credential=credential)
    second_certificate = new_generation.credential.get_certificate_serializer().as_pem()
    make_entry(target)
    create_checkpoint()

    document = create_evidence_export(AuditLog.objects.all(), {})
    assert len(document['evidence']['checkpoints']) == 2
    assert len(document['evidence']['certificates']) == 2
    report = verify_evidence_package(document, [first_certificate, second_certificate])
    assert report['ok']
    assert report['checkpoints_checked'] == 2

    incomplete_trust = verify_evidence_package(document, [second_certificate])
    assert not incomplete_trust['ok']
    assert 'UNTRUSTED_CERTIFICATE' in {finding['code'] for finding in incomplete_trust['findings']}


def test_filtered_export_is_snapshot_signed(credential, target):
    enable_signing(credential)
    make_entry(target)
    other = get_user_model().objects.create_user(username='other-target')
    AuditLog.create_entry(
        AuditLog.OperationType.USER_CREATED,
        other,
        'Other target',
        details={'message': 'other'},
    )
    create_checkpoint()
    filters = {'operation_type': AuditLog.OperationType.CREDENTIAL_ISSUED}
    document = create_evidence_export(
        AuditLog.objects.filter(operation_type=AuditLog.OperationType.CREDENTIAL_ISSUED),
        filters,
    )

    assert document['evidence']['scope'] == 'filtered'
    assert document['evidence']['complete_chain'] is False
    assert document['snapshot_signature'] is not None
    report = verify_evidence_package(document, [trusted_certificate(credential)])
    assert report['ok']
    assert report['complete_chain'] is False


def test_filtered_export_lists_snapshot_signing_certificate_after_rotation(credential, target):
    enable_signing(credential)
    make_entry(target)
    create_checkpoint()
    first_certificate = trusted_certificate(credential)
    new_generation = TraceabilityCredentialService.rotate(traceability_credential=credential)
    second_certificate = new_generation.credential.get_certificate_serializer().as_pem()

    document = create_evidence_export(AuditLog.objects.all(), {'target_object_id': str(target.pk)})

    fingerprints = {certificate['fingerprint_sha256'] for certificate in document['evidence']['certificates']}
    assert new_generation.credential.certificate_or_error.sha256_fingerprint.upper() in fingerprints
    assert verify_evidence_package(document, [first_certificate, second_certificate])['ok']


def test_filtered_export_requires_signing_configuration(credential, target):
    make_entry(target)
    with pytest.raises(ValidationError, match='require audit signing'):
        create_evidence_export(AuditLog.objects.all(), {'operation_type': AuditLog.OperationType.CREDENTIAL_ISSUED})


def test_filtered_snapshot_tampering_is_detected(credential, target):
    enable_signing(credential)
    make_entry(target)
    make_entry(target)
    create_checkpoint()
    document = create_evidence_export(AuditLog.objects.all(), {'target_object_id': str(target.pk)})
    altered = copy.deepcopy(document)
    altered['evidence']['entries'][0]['target_display'] = 'tampered'

    report = verify_evidence_package(altered, [trusted_certificate(credential)])
    assert not report['ok']
    codes = {finding['code'] for finding in report['findings']}
    assert 'CHECKPOINT_PAYLOAD_MISMATCH' in codes or 'HASH_MISMATCH' in codes


def test_filtered_snapshot_signature_tampering_is_detected(credential, target):
    enable_signing(credential)
    make_entry(target)
    create_checkpoint()
    document = create_evidence_export(
        AuditLog.objects.all(), {'operation_type': AuditLog.OperationType.CREDENTIAL_ISSUED}
    )
    altered = copy.deepcopy(document)
    altered['snapshot_signature']['signature'] = 'AAAA'

    report = verify_evidence_package(altered, [trusted_certificate(credential)])
    assert not report['ok']
    assert 'INVALID_SNAPSHOT_SIGNATURE' in {finding['code'] for finding in report['findings']}


def test_export_limit_is_enforced(credential, target, monkeypatch):
    make_entry(target)
    make_entry(target)
    monkeypatch.setattr(audit_log_export, 'MAX_EXPORT_ENTRIES', 1)
    with pytest.raises(ValidationError, match='Narrow the audit log filters'):
        create_evidence_export(AuditLog.objects.all(), {})


def test_checkpoint_limit_bounds_loaded_history(
    credential: TraceabilityCredentialModel, target: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Stop loading historical checkpoint objects as soon as the export exceeds its limit."""
    enable_signing(credential)
    create_checkpoint()
    for _ in range(2):
        make_entry(target)
        create_checkpoint()
    monkeypatch.setattr(audit_log_export, 'MAX_EXPORT_CHECKPOINTS', 1)

    loaded = []
    original_from_db = AuditLogCheckpoint.from_db

    def from_db(
        _cls: type[AuditLogCheckpoint], db: str, field_names: list[str], values: list[Any], **kwargs: Any
    ) -> AuditLogCheckpoint:
        entry = original_from_db(db, field_names, values, **kwargs)
        loaded.append(entry)
        return entry

    monkeypatch.setattr(AuditLogCheckpoint, 'from_db', classmethod(from_db))
    with pytest.raises(ValidationError, match='limited to 1 checkpoints'):
        create_evidence_export(AuditLog.objects.all(), {})

    assert len(loaded) == audit_log_export.MAX_EXPORT_CHECKPOINTS + 1


def test_export_view_requires_only_audit_view_permission(target):
    make_entry(target)
    user = get_user_model().objects.create_user(username='audit-reader')
    user.user_permissions.add(Permission.objects.get(codename='view_audit_log'))
    client = Client()
    client.force_login(user)
    page = client.get(reverse('management:audit-log-export'))
    assert page.status_code == 200
    assert b'Export scope' in page.content
    response = client.get(reverse('management:audit-log-export-download'))
    assert response.status_code == 200
    assert response['Content-Type'] == 'application/json'
    assert response['Content-Disposition'] == 'attachment; filename="trustpoint-audit-evidence.json"'
    assert response['Cache-Control'] == 'no-store'
    document = response.json()
    assert document['format'] == EVIDENCE_FORMAT
    assert document['evidence']['scope'] == 'full'


def test_filtered_view_requires_traceability_permission(credential, target):
    make_entry(target)
    user = get_user_model().objects.create_user(username='filtered-reader')
    user.user_permissions.add(Permission.objects.get(codename='view_audit_log'))
    client = Client()
    client.force_login(user)
    response = client.get(reverse('management:audit-log-export-download') + '?operation_type=CREDENTIAL_ISSUED')
    assert response.status_code == 403


def test_filtered_view_rejects_unavailable_signing(credential, target):
    make_entry(target)
    user = get_user_model().objects.create_user(username='filtered-signer')
    user.user_permissions.add(Permission.objects.get(codename='view_audit_log'))
    user.user_permissions.add(Permission.objects.get(codename='manage_traceability_credentials'))
    client = Client()
    client.force_login(user)
    response = client.get(
        reverse('management:audit-log-export-download') + '?operation_type=CREDENTIAL_ISSUED',
        follow=True,
    )
    assert response.status_code == 200
    assert 'Filtered evidence exports require' in response.content.decode()


def test_offline_verifier_command(credential, target, tmp_path):
    document, trusted = full_export_with_checkpoint(credential, target)
    export_file = tmp_path / 'evidence.json'
    trusted_file = tmp_path / 'trusted.pem'
    export_file.write_text(json.dumps(document))
    trusted_file.write_bytes(trusted)
    verifier = Path(__file__).parents[2] / 'util' / 'audit_log_export.py'
    result = subprocess.run(
        [
            sys.executable,
            '-I',
            str(verifier),
            str(export_file),
            '--trusted-certificate',
            str(trusted_file),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert 'Verified 2 entries and 1 checkpoints' in result.stdout

    altered = copy.deepcopy(document)
    altered['evidence']['entries'][0]['target_display'] = 'tampered'
    export_file.write_text(json.dumps(altered))
    failed = subprocess.run(
        [
            sys.executable,
            '-I',
            str(verifier),
            str(export_file),
            '--trusted-certificate',
            str(trusted_file),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert failed.returncode == 1
    assert 'HASH_MISMATCH' in failed.stdout
