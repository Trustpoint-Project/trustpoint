# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Signed audit checkpoint regression tests."""

from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import timedelta
from threading import Event
from typing import Any

import pytest
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission
from django.core.exceptions import ValidationError
from django.core.management import call_command
from django.db import OperationalError, connection, connections
from django.test import Client
from django.urls import reverse
from django.utils import timezone
from django_q.models import Schedule

from management.models import LoggingConfig
from management.models.audit_log import AuditLog
from management.models.audit_signing import AuditLogCheckpoint, AuditSigningConfig
from management.models.traceability import TraceabilityCredentialModel
from management.services.audit_integrity import verify_audit_chain
from management.services.audit_signing import (
    DEFAULT_SCHEDULE_INTERVAL_MINUTES,
    SCHEDULE_NAME,
    create_checkpoint,
    maybe_sign_checkpoint,
    sync_signing_schedule,
)
from management.services.traceability_signing import TraceabilityCredentialService

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
        name='audit-checkpoint-test',
    )
    # Backend setup emits crypto-config events; isolate checkpoint coverage in each test.
    AuditLog.objects.all().delete()
    return credential


def enable(credential: TraceabilityCredentialModel, *, events: int = 100, minutes: int | None = None) -> None:
    config = AuditSigningConfig.get()
    config.enabled = True
    config.traceability_credential = credential
    config.checkpoint_event_interval = events
    config.checkpoint_time_interval_minutes = minutes
    config.full_clean()
    config.save()


def make_entry(target, message: str = 'event') -> AuditLog:
    return AuditLog.create_entry(
        AuditLog.OperationType.USER_CREATED,
        target,
        'User: signing-target',
        details={'message': message},
    )


@pytest.fixture
def target():
    return get_user_model().objects.create_user(username='signing-target')


def test_genesis_checkpoint_and_signature_verify(credential):
    enable(credential)
    genesis = create_checkpoint()
    assert genesis is not None
    assert genesis.last_sequence == 0
    assert genesis.entry_count == 0

    report = verify_audit_chain()
    assert report.ok
    assert report.checkpoints_checked == 1


def test_event_threshold_creates_one_checkpoint(credential, target):
    enable(credential, events=3)
    create_checkpoint()

    make_entry(target, 'one')
    make_entry(target, 'two')
    assert maybe_sign_checkpoint() is None

    make_entry(target, 'three')
    checkpoint = maybe_sign_checkpoint()
    assert checkpoint is not None
    assert checkpoint.first_sequence == 1
    assert checkpoint.last_sequence == 3
    assert checkpoint.entry_count == 3
    assert maybe_sign_checkpoint() is None

    report = verify_audit_chain()
    assert report.ok
    assert report.unsigned_entries == 0
    assert report.checkpoints_checked == 2


def test_checkpoint_signing_is_visible_as_audit_event(credential, django_capture_on_commit_callbacks):
    enable(credential, events=1)
    with django_capture_on_commit_callbacks(execute=True):
        create_checkpoint()

    event = AuditLog.objects.get(operation_type=AuditLog.OperationType.AUDIT_CHECKPOINT_SIGNED)
    assert 'Audit checkpoint 1 (genesis)' == event.target_display
    assert event.actor_label == ''
    assert event.details['checkpoint_number'] == 1
    assert event.details['last_sequence'] == 0

    report = verify_audit_chain()
    assert report.ok
    assert report.unsigned_entries == 1
    assert not report.findings
    # The signing event itself must not trigger another checkpoint.
    assert maybe_sign_checkpoint() is None
    assert create_checkpoint() is None


def test_checkpoint_crypto_events_do_not_trigger_signing(
    credential: TraceabilityCredentialModel,
    target: Any,
    django_capture_on_commit_callbacks: Any,
) -> None:
    """Retain internal crypto events without letting them trigger further checkpoints."""
    LoggingConfig.objects.update_or_create(pk=1, defaults={'crypto_backend_audit_enabled': True})
    enable(credential, events=1)
    make_entry(target)
    with django_capture_on_commit_callbacks(execute=True):
        checkpoint = create_checkpoint()
    assert checkpoint is not None
    crypto_event = AuditLog.objects.get(operation_type=AuditLog.OperationType.CRYPTO_SIGN)
    assert crypto_event.details['audit_checkpoint_signing'] is True
    assert crypto_event.sequence > checkpoint.last_sequence
    assert maybe_sign_checkpoint() is None
    assert create_checkpoint() is None
    report = verify_audit_chain()
    assert report.ok
    assert not report.findings

    # Ordinary crypto operations must still count toward the checkpoint threshold.
    TraceabilityCredentialService.sign(traceability_credential=credential, data=b'business operation')
    assert maybe_sign_checkpoint() is not None
    assert AuditLogCheckpoint.objects.count() == report.checkpoints_checked + 1
    assert verify_audit_chain().ok


def test_pending_events_below_interval_do_not_warn(credential, target):
    enable(credential, events=2, minutes=60)
    create_checkpoint()
    make_entry(target, 'one')

    report = verify_audit_chain()
    assert report.ok
    assert report.unsigned_entries == 1
    assert not report.findings

    make_entry(target, 'two')
    report = verify_audit_chain()
    assert report.ok
    assert [finding.code.value for finding in report.findings] == ['UNSIGNED_EVENTS']

    checkpoint = maybe_sign_checkpoint()
    assert checkpoint is not None
    report = verify_audit_chain()
    assert report.ok
    assert report.unsigned_entries == 0
    assert not report.findings


def test_time_interval_triggers_checkpoint(credential, target):
    enable(credential, events=100, minutes=1)
    genesis = create_checkpoint()
    assert genesis is not None
    make_entry(target, 'one')
    AuditLogCheckpoint.objects.filter(pk=genesis.pk).update(signed_at=timezone.now() - timedelta(minutes=2))

    checkpoint = maybe_sign_checkpoint()
    assert checkpoint is not None
    assert checkpoint.last_sequence == 1


def test_checkpoint_resets_timer_to_its_deadline(
    credential: TraceabilityCredentialModel, target: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A checkpoint between timer ticks must move the next run to its own deadline."""
    enable(credential, events=100, minutes=60)
    start = timezone.now()
    sync_signing_schedule(enabled=True, time_interval_minutes=60)
    signed_at = start + timedelta(minutes=1)
    monkeypatch.setattr('management.services.audit_signing.timezone.now', lambda: signed_at)
    checkpoint = create_checkpoint()
    assert checkpoint is not None
    deadline = signed_at + timedelta(minutes=60)
    timer = Schedule.objects.get(name=SCHEDULE_NAME)
    assert timer.next_run == deadline

    make_entry(target, 'pending before the deadline')
    monkeypatch.setattr('management.services.audit_signing.timezone.now', lambda: deadline)
    # The scheduler advances the recurring timer before the worker executes the task.
    timer.next_run = timer.calculate_next_run()
    timer.save()
    assert maybe_sign_checkpoint() is not None
    assert Schedule.objects.get(name=SCHEDULE_NAME).next_run == deadline + timedelta(minutes=60)


@pytest.mark.parametrize('overdue', [False, True])
def test_schedule_uses_existing_checkpoint_deadline(
    credential: TraceabilityCredentialModel, monkeypatch: pytest.MonkeyPatch, *, overdue: bool
) -> None:
    """Changing the interval uses the last signing time and runs overdue work immediately."""
    enable(credential, minutes=60)
    checkpoint = create_checkpoint()
    assert checkpoint is not None
    now = checkpoint.signed_at + timedelta(minutes=90 if overdue else 1)
    monkeypatch.setattr('management.services.audit_signing.timezone.now', lambda: now)

    sync_signing_schedule(enabled=True, time_interval_minutes=30)

    assert Schedule.objects.get(name=SCHEDULE_NAME).next_run == max(now, checkpoint.signed_at + timedelta(minutes=30))


def test_tampered_checkpoint_signature_is_detected(credential, target):
    enable(credential, events=1)
    create_checkpoint()
    make_entry(target, 'one')
    checkpoint = maybe_sign_checkpoint()
    assert checkpoint is not None
    AuditLogCheckpoint.objects.filter(pk=checkpoint.pk).update(signature=b'invalid')

    report = verify_audit_chain()
    assert not report.ok
    codes = {finding.code.value for finding in report.findings}
    assert 'INVALID_CHECKPOINT_SIGNATURE' in codes


def test_rotation_preserves_old_checkpoint_verification(credential, target):
    enable(credential, events=1)
    create_checkpoint()
    make_entry(target, 'one')
    first = maybe_sign_checkpoint()
    assert first is not None

    TraceabilityCredentialService.rotate(traceability_credential=credential)
    make_entry(target, 'two')
    second = maybe_sign_checkpoint()
    assert second is not None
    assert first.traceability_generation_id != second.traceability_generation_id

    report = verify_audit_chain()
    assert report.ok
    assert report.checkpoints_checked == 3


def test_signing_failure_does_not_block_events(credential, target, monkeypatch):
    enable(credential, events=1)
    create_checkpoint()

    def fail_signing(**_kwargs):
        raise RuntimeError('backend unavailable')

    monkeypatch.setattr(TraceabilityCredentialService, 'sign', fail_signing)
    entry = make_entry(target, 'still written')
    assert maybe_sign_checkpoint() is None
    assert AuditLog.objects.filter(pk=entry.pk).exists()
    config = AuditSigningConfig.get()
    assert 'backend unavailable' in config.last_signing_error
    assert AuditLogCheckpoint.objects.count() == 1


def test_retired_credential_fails_safely(credential, target):
    enable(credential, events=1)
    create_checkpoint()
    TraceabilityCredentialService.retire(credential)

    make_entry(target, 'after retirement')
    assert maybe_sign_checkpoint() is None
    config = AuditSigningConfig.get()
    assert config.last_signing_error
    assert AuditLogCheckpoint.objects.count() == 1


def test_configuration_validation_requires_usable_credential():
    config = AuditSigningConfig(
        pk=1,
        enabled=True,
        checkpoint_event_interval=100,
        checkpoint_time_interval_minutes=None,
    )
    with pytest.raises(ValidationError):
        config.full_clean()

    config.enabled = False
    config.checkpoint_event_interval = 0
    with pytest.raises(ValidationError):
        config.full_clean()


def test_verify_page_links_credential_and_certificate(credential):
    enable(credential)
    create_checkpoint()
    assert credential.current_generation is not None
    certificate = credential.current_generation.credential.certificate_or_error
    user = get_user_model().objects.create_user(username='audit-link-reader')
    user.user_permissions.add(Permission.objects.get(codename='view_audit_log'))
    client = Client()
    client.force_login(user)

    response = client.get(reverse('management:audit-log-verify'))
    content = response.content.decode()
    assert response.status_code == 200
    assert reverse('management:traceability_credential_detail', args=[credential.pk]) in content
    assert reverse('pki:certificate-detail', args=[certificate.pk]) in content


def test_callback_swallows_initial_configuration_lookup_error(monkeypatch):
    class BrokenManager:
        def filter(self, *_args, **_kwargs):
            raise OperationalError('database read failed')

    class BrokenConfig:
        objects = BrokenManager()

    monkeypatch.setattr('management.services.audit_signing.AuditSigningConfig', BrokenConfig)
    assert maybe_sign_checkpoint() is None


@pytest.mark.django_db(transaction=True)
def test_audit_insert_survives_checkpoint_configuration_lookup_error(target, monkeypatch):
    class BrokenManager:
        def filter(self, *_args, **_kwargs):
            raise OperationalError('database read failed')

    class BrokenConfig:
        objects = BrokenManager()

    monkeypatch.setattr('management.services.audit_signing.AuditSigningConfig', BrokenConfig)
    entry = make_entry(target, 'callback survives')
    assert AuditLog.objects.filter(pk=entry.pk).exists()


def test_schedule_frequency_tracks_configured_interval():
    sync_signing_schedule(enabled=True, time_interval_minutes=1)
    assert Schedule.objects.get(name=SCHEDULE_NAME).minutes == 1

    sync_signing_schedule(enabled=True, time_interval_minutes=17)
    assert Schedule.objects.get(name=SCHEDULE_NAME).minutes == 17

    sync_signing_schedule(enabled=True, time_interval_minutes=None)
    assert Schedule.objects.get(name=SCHEDULE_NAME).minutes == DEFAULT_SCHEDULE_INTERVAL_MINUTES

    sync_signing_schedule(enabled=False, time_interval_minutes=None)
    assert not Schedule.objects.filter(name=SCHEDULE_NAME).exists()


def test_mismatched_signing_generation_is_not_stored(credential, target, monkeypatch):
    enable(credential, events=1)
    create_checkpoint()
    make_entry(target, 'one')
    original_sign = TraceabilityCredentialService.sign

    def mismatched_sign(**kwargs):
        result = original_sign(**kwargs)
        return replace(result, generation_id=result.generation_id + 1)

    monkeypatch.setattr(TraceabilityCredentialService, 'sign', mismatched_sign)
    with pytest.raises(ValidationError):
        create_checkpoint()
    assert AuditLogCheckpoint.objects.count() == 1


@pytest.mark.django_db(transaction=True)
def test_checkpoint_locks_generation_before_signing(credential, target, monkeypatch):
    if connection.vendor != 'postgresql':
        pytest.skip('Credential row-lock ordering requires PostgreSQL')

    enable(credential, events=1)
    create_checkpoint()
    make_entry(target, 'one')

    original_sign = TraceabilityCredentialService.sign
    signing_started = Event()
    release_signing = Event()
    rotation_started = Event()

    def paused_sign(*, traceability_credential, data):
        signing_started.set()
        assert release_signing.wait(timeout=10)
        return original_sign(traceability_credential=traceability_credential, data=data)

    def sign_checkpoint():
        try:
            return create_checkpoint()
        finally:
            connections.close_all()

    def rotate():
        rotation_started.set()
        try:
            return TraceabilityCredentialService.rotate(traceability_credential=credential)
        finally:
            connections.close_all()

    monkeypatch.setattr(TraceabilityCredentialService, 'sign', paused_sign)
    with ThreadPoolExecutor(max_workers=1) as checkpoint_pool:
        checkpoint_future = checkpoint_pool.submit(sign_checkpoint)
        try:
            assert signing_started.wait(timeout=10)
            with ThreadPoolExecutor(max_workers=1) as rotation_pool:
                rotation_future = rotation_pool.submit(rotate)
                assert rotation_started.wait(timeout=10)
                # Rotation must block on the credential lock held by checkpoint creation.
                time.sleep(0.5)
                assert not rotation_future.done()
                release_signing.set()
                checkpoint = checkpoint_future.result(timeout=30)
                rotation_future.result(timeout=30)
        finally:
            release_signing.set()

    assert checkpoint is not None
    payload = json.loads(checkpoint.payload)
    assert payload['signer']['generation_id'] == checkpoint.traceability_generation_id
    assert payload['signer']['certificate_fingerprint_sha256'] == checkpoint.certificate_fingerprint_sha256
    assert verify_audit_chain().ok


def test_signing_view_enables_and_creates_baseline(credential):
    user = get_user_model().objects.create_superuser(username='audit-signing-admin', password='test-password')
    client = Client()
    client.force_login(user)
    page = client.get(reverse('management:audit-log-signing'))
    assert page.status_code == 200
    response = client.post(
        reverse('management:audit-log-signing'),
        {
            'enabled': 'on',
            'traceability_credential': credential.pk,
            'checkpoint_event_interval': 25,
            'checkpoint_time_interval_minutes': 60,
        },
    )
    assert response.status_code == 302
    config = AuditSigningConfig.get()
    assert config.enabled
    assert config.checkpoint_event_interval == 25
    assert AuditLogCheckpoint.objects.filter(last_sequence=0).exists()
    page = client.get(reverse('management:audit-log-signing'))
    assert page.status_code == 200
    assert b'Signed checkpoints' in page.content


def test_verify_view_refuses_logs_above_ui_limit(target, monkeypatch):
    make_entry(target)
    user = get_user_model().objects.create_user(username='audit-large-reader')
    user.user_permissions.add(Permission.objects.get(codename='view_audit_log'))
    client = Client()
    client.force_login(user)
    monkeypatch.setattr('management.views.audit_log.MAX_UI_VERIFY_ENTRIES', 0)
    response = client.get(reverse('management:audit-log-verify'))
    assert response.status_code == 200
    assert 'too large to verify in the browser' in response.content.decode()


def test_verify_view_requires_only_audit_view_permission(target):
    make_entry(target)
    user = get_user_model().objects.create_user(username='audit-verifier')
    user.user_permissions.add(Permission.objects.get(codename='view_audit_log'))
    client = Client()
    client.force_login(user)
    response = client.get(reverse('management:audit-log-verify'))
    assert response.status_code == 200
    content = response.content.lower()
    assert b'audit hash chain is intact' in content
    assert b'checkpoint signing is incomplete' in content
    assert b'all retained checkpoint signatures are valid' not in content
