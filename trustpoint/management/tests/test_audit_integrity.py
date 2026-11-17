# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Audit hash chain and verification regression tests."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

import pytest
from django.contrib.auth import get_user_model
from django.contrib.contenttypes.models import ContentType
from django.core.exceptions import ValidationError
from django.db import connection, connections

from management.models.audit_log import GENESIS_HASH, AuditLog
from management.services.audit_integrity import AuditFindingCode, verify_audit_chain

pytestmark = pytest.mark.django_db


@pytest.fixture
def target():
    return get_user_model().objects.create_user(username='audit-target')


def make_entry(target, message='event'):
    return AuditLog.create_entry(
        AuditLog.OperationType.USER_CREATED,
        target,
        'User: audit-target',
        details={'message': message},
    )


def test_entries_form_a_deterministic_chain(target):
    first = make_entry(target, 'first')
    second = make_entry(target, 'second')
    third = make_entry(target, 'third')

    assert [first.sequence, second.sequence, third.sequence] == [1, 2, 3]
    assert first.previous_hash == GENESIS_HASH
    assert second.previous_hash == first.entry_hash
    assert third.previous_hash == second.entry_hash
    assert first.entry_hash == first.calculate_entry_hash()

    report = verify_audit_chain()
    assert report.ok
    assert report.entries_checked == 3
    assert report.unsigned_entries == 3
    assert [finding.code for finding in report.findings] == [AuditFindingCode.SIGNING_NOT_CONFIGURED]


def test_direct_model_create_is_chained(target):
    entry = AuditLog.objects.create(
        operation_type=AuditLog.OperationType.USER_CREATED,
        target_content_type=ContentType.objects.get_for_model(type(target)),
        target_object_id=target.pk,
        target_display='User: audit-target',
    )
    entry.refresh_from_db()
    assert entry.sequence == 1
    assert entry.previous_hash == GENESIS_HASH
    assert entry.target_object_id == str(target.pk)
    assert entry.entry_hash == entry.calculate_entry_hash()


def test_modified_entry_is_detected(target):
    first = make_entry(target, 'first')
    second = make_entry(target, 'second')
    AuditLog.objects.filter(pk=first.pk).update(target_display='tampered')

    report = verify_audit_chain()
    assert not report.ok
    assert AuditFindingCode.HASH_MISMATCH in {finding.code for finding in report.findings}
    assert second.pk


def test_missing_entry_is_detected(target):
    make_entry(target, 'first')
    middle = make_entry(target, 'second')
    make_entry(target, 'third')
    AuditLog.objects.filter(pk=middle.pk).delete()

    report = verify_audit_chain()
    assert not report.ok
    codes = {finding.code for finding in report.findings}
    assert AuditFindingCode.MISSING_ENTRY in codes
    assert AuditFindingCode.PREVIOUS_HASH_MISMATCH in codes


def test_reordered_entries_are_detected(target):
    make_entry(target, 'first')
    second = make_entry(target, 'second')
    third = make_entry(target, 'third')

    AuditLog.objects.filter(pk=second.pk).update(sequence=100)
    AuditLog.objects.filter(pk=third.pk).update(sequence=2)
    AuditLog.objects.filter(pk=second.pk).update(sequence=3)

    report = verify_audit_chain()
    assert not report.ok
    codes = {finding.code for finding in report.findings}
    assert AuditFindingCode.HASH_MISMATCH in codes
    assert AuditFindingCode.PREVIOUS_HASH_MISMATCH in codes


def test_content_type_removal_keeps_audit_row(target):
    content_type = ContentType.objects.create(app_label='legacy_app', model='removed_model')
    entry = AuditLog.objects.create(
        operation_type=AuditLog.OperationType.USER_CREATED,
        target_content_type=content_type,
        target_object_id='1',
        target_display='Legacy target',
    )
    assert entry.target_type == 'legacy_app.removed_model'

    content_type.delete()
    entry.refresh_from_db()
    assert entry.target_content_type is None
    assert entry.target_type == 'legacy_app.removed_model'


def test_delete_guard_rejects_model_deletion(target):
    entry = make_entry(target)
    with pytest.raises(ValidationError):
        entry.delete()


def test_empty_chain_verifies_with_signing_warning(target):
    assert target
    report = verify_audit_chain()
    assert report.ok
    assert report.entries_checked == 0
    assert [finding.code for finding in report.findings] == [AuditFindingCode.SIGNING_NOT_CONFIGURED]


@pytest.mark.django_db(transaction=True)
def test_concurrent_appends_remain_contiguous(target):
    if connection.vendor != 'postgresql':
        pytest.skip('Concurrent write retries require PostgreSQL')

    def create(index: int) -> int:
        try:
            return make_entry(target, f'concurrent-{index}').sequence
        finally:
            connections.close_all()

    with ThreadPoolExecutor(max_workers=4) as pool:
        sequences = list(pool.map(create, range(20)))

    assert sorted(sequences) == list(range(1, 21))
    report = verify_audit_chain()
    assert report.ok
    assert report.entries_checked == 20
