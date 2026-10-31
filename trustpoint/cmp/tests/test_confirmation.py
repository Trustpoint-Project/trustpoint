# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Regression tests for bounded explicit CMP confirmation and bootstrap lifetime."""

from datetime import timedelta
from unittest.mock import patch

import pytest
from django.core.exceptions import ImproperlyConfigured, ValidationError
from django.db import connection
from django.utils import timezone
from pyasn1.codec.der import decoder
from pyasn1_modules import rfc4210
from trustpoint_core.oid import HmacAlgorithm

from cmp.confirmation import expire_confirmation, expire_due_confirmations, initialize_confirmation_expiry
from cmp.models import CmpTransactionModel
from devices.secrets import assign_secret
from management.models import SecurityConfig
from onboarding.enums import OnboardingProtocol, OnboardingStatus
from pki.models import RevokedCertificateModel
from pki.tests.credential_helpers import issue_test_credential
from request.cmp_transaction_state import CmpTransactionState
from request.clients.cmp_client import CmpClient
from request.message_builder.cmp import CmpPkiHeaderBuilding
from request.message_responder.cmp import CmpMessageResponder
from request.operation_processor.cert_conf import CertConfProcessor
from request.request_context import CmpCertConfRequestContext, CmpCertificateRequestContext
from request.security_hardening import authenticate_cmp_request


@pytest.fixture
def pending_confirmation(cmp_device_with_onboarding, rsa_private_key):
    device = cmp_device_with_onboarding['device']
    config = device.onboarding_config
    config.onboarding_protocol = OnboardingProtocol.CMP_SHARED_SECRET
    config.save(update_fields=['onboarding_protocol'])
    assign_secret(config, 'cmp_shared_secret')
    issued = issue_test_credential(device, 'domain_credential', public_key=rsa_private_key.public_key())
    context = CmpCertificateRequestContext(
        device=device,
        domain=device.domain,
        issued_certificate=issued.credential.get_certificate(),
        issuer_credential=device.domain.issuing_ca.credential,
    )
    record = CmpTransactionModel.objects.create(
        transaction_id='aabbccdd',
        operation='initialization',
        request_body_type='ir',
        request_der=b'request',
        device=device,
        domain=device.domain,
    )
    return CmpTransactionState.mark_issued(record.pk, context), context


def _make_due(record):
    record.confirmation_deadline = timezone.now() - timedelta(seconds=1)
    record.save(update_fields=['confirmation_deadline'])


def test_issuance_persists_deadline_and_snapshots_policy(pending_confirmation, settings):
    record, context = pending_confirmation
    deadline = record.confirmation_deadline
    assert timezone.now() + timedelta(seconds=290) < deadline < timezone.now() + timedelta(seconds=301)
    settings.TRUSTPOINT_CMP_CONFIRMATION_TIMEOUT_SECONDS = 900
    settings.TRUSTPOINT_CMP_CONFIRMATION_TIMEOUT_POLICY = 'log'
    replayed = CmpTransactionState.mark_issued(record.pk, context)
    assert replayed.confirmation_deadline == deadline
    assert replayed.confirmation_timeout_policy == 'revoke'


def test_implicit_confirmation_has_no_deadline(pending_confirmation):
    record, context = pending_confirmation
    record.implicit_confirm = True
    record.confirmation_deadline = None
    record.save(update_fields=['implicit_confirm', 'confirmation_deadline'])
    record = CmpTransactionState.mark_issued(record.pk, context)
    assert record.confirmation_deadline is None
    assert not expire_confirmation(record.pk, now=timezone.now() + timedelta(days=1))


def test_timeout_revokes_once_and_invalidates_bootstrap_without_completing_onboarding(pending_confirmation):
    record, _ = pending_confirmation
    config = record.device.onboarding_config
    previous_version = config.cmp_secret_version
    _make_due(record)
    assert expire_due_confirmations() == 1
    assert expire_due_confirmations() == 0
    record.refresh_from_db()
    config.refresh_from_db()
    assert record.status == CmpTransactionModel.Status.REJECTED
    assert record.confirmed_at is None
    assert RevokedCertificateModel.objects.filter(certificate=record.final_certificate).count() == 1
    assert not config.cmp_shared_secret
    assert not config.est_password
    assert config.cmp_secret_version == previous_version + 1
    assert config.onboarding_status == OnboardingStatus.PENDING


def test_secret_rotation_expires_abandoned_transaction_even_without_worker(pending_confirmation):
    record, _ = pending_confirmation
    config = record.device.onboarding_config
    with pytest.raises(ValidationError, match='outstanding CMP'):
        assign_secret(config, 'cmp_shared_secret')
    _make_due(record)
    new_secret = assign_secret(config, 'cmp_shared_secret')
    config.refresh_from_db()
    record.refresh_from_db()
    assert new_secret and config.cmp_shared_secret == new_secret
    assert record.status == CmpTransactionModel.Status.REJECTED


def test_log_policy_records_rejection_without_revocation(
    pending_confirmation, django_capture_on_commit_callbacks, caplog
):
    record, _ = pending_confirmation
    record.confirmation_timeout_policy = 'log'
    record.save(update_fields=['confirmation_timeout_policy'])
    _make_due(record)
    with django_capture_on_commit_callbacks(execute=True):
        assert expire_confirmation(record.pk)
    record.refresh_from_db()
    assert record.status == CmpTransactionModel.Status.REJECTED
    assert 'policy: log' in record.detail
    assert 'timed out' in caplog.text
    assert not RevokedCertificateModel.objects.filter(certificate=record.final_certificate).exists()
    record.device.onboarding_config.refresh_from_db()
    assert not record.device.onboarding_config.cmp_shared_secret


def test_revocation_failure_preserves_state_for_retry(pending_confirmation):
    record, _ = pending_confirmation
    _make_due(record)
    with patch('cmp.confirmation.revoke_certificate', side_effect=RuntimeError('backend unavailable')):
        assert expire_due_confirmations() == 0
    record.refresh_from_db()
    record.device.onboarding_config.refresh_from_db()
    assert record.status == CmpTransactionModel.Status.ISSUED
    assert record.device.onboarding_config.cmp_shared_secret
    assert expire_due_confirmations() == 1


def test_confirmed_transaction_is_never_expired(pending_confirmation):
    record, _ = pending_confirmation
    context = CmpCertConfRequestContext(cmp_transaction=record, cert_conf_status=0)
    CertConfProcessor().process_operation(context)
    _make_due(record)
    assert not expire_confirmation(record.pk)
    record.refresh_from_db()
    assert record.confirmed_at is not None
    assert not RevokedCertificateModel.objects.filter(certificate=record.final_certificate).exists()


def test_late_confirmation_cannot_complete_expired_onboarding(pending_confirmation):
    record, _ = pending_confirmation
    _make_due(record)
    context = CmpCertConfRequestContext(cmp_transaction=record, cert_conf_status=0)
    with pytest.raises(ValueError, match='no longer awaiting'):
        CertConfProcessor().process_operation(context)
    record.refresh_from_db()
    assert record.status == CmpTransactionModel.Status.REJECTED
    assert record.confirmed_at is None


def test_processor_reloads_state_before_accepting_stale_confirmation(pending_confirmation):
    record, _ = pending_confirmation
    context = CmpCertConfRequestContext(cmp_transaction=record, cert_conf_status=0)
    CmpTransactionModel.objects.filter(pk=record.pk).update(confirmation_deadline=timezone.now())
    with pytest.raises(ValueError, match='no longer awaiting'):
        CertConfProcessor().process_operation(context)
    assert expire_due_confirmations() == 1


def test_transaction_lookup_applies_expiry(pending_confirmation):
    record, _ = pending_confirmation
    _make_due(record)
    found = CmpTransactionState.get_by_transaction_id(record.transaction_id)
    assert found.status == CmpTransactionModel.Status.REJECTED


@pytest.mark.parametrize('late', [False, True])
def test_protected_confirmation_respects_persisted_deadline(pending_confirmation, late):
    record, issuance_context = pending_confirmation
    SecurityConfig.objects.create()
    record.last_client_nonce = b'previous-client'
    record.last_server_nonce = b'previous-server'
    record.save(update_fields=['last_client_nonce', 'last_server_nonce'])
    if late:
        _make_due(record)
    certificate = issuance_context.issued_certificate
    message = rfc4210.PKIMessage()
    header = message['header']
    header['pvno'] = 2
    header['sender']['rfc822Name'] = 'device@example.test'
    header['recipient']['rfc822Name'] = 'ca@example.test'
    header['transactionID'] = bytes.fromhex(record.transaction_id)
    header['senderNonce'] = b'fresh-client'
    header['recipNonce'] = record.last_server_nonce
    message['header'] = CmpPkiHeaderBuilding._prepare_protection_algorithm_pbm(
        header,
        hmac_algorithm=HmacAlgorithm.HMAC_SHA256,
    )
    cert_hash = certificate.fingerprint(certificate.signature_hash_algorithm)
    message['body']['certConf'][0]['certHash'] = cert_hash
    message['body']['certConf'][0]['certReqId'] = 0
    context = CmpCertConfRequestContext(
        parsed_message=message,
        cmp_transaction_id=record.transaction_id,
        cert_req_id=0,
        cert_hash=cert_hash,
        cert_conf_status=0,
        cmp_server_host='example.test',
        cmp_shared_secret=record.device.onboarding_config.cmp_shared_secret,
    )
    CmpClient(context)._add_protection_shared_secret(message)
    context.cmp_shared_secret = None
    if late:
        with pytest.raises(ValueError, match='no longer awaiting'):
            authenticate_cmp_request(context)
    else:
        authenticate_cmp_request(context)
        CertConfProcessor().process_operation(context)
    record.refresh_from_db()
    assert (record.confirmed_at is not None) is not late
    assert (record.status == CmpTransactionModel.Status.REJECTED) is late


def test_certification_timeout_preserves_existing_bootstrap_configuration(pending_confirmation):
    record, _ = pending_confirmation
    record.operation = 'certification'
    record.save(update_fields=['operation'])
    original_secret = record.device.onboarding_config.cmp_shared_secret
    _make_due(record)
    assert expire_confirmation(record.pk)
    record.device.onboarding_config.refresh_from_db()
    assert record.device.onboarding_config.cmp_shared_secret == original_secret


def test_upgrade_backfills_legacy_deadline_and_installs_recurring_sweep(pending_confirmation):
    from django_q.models import Schedule

    record, _ = pending_confirmation
    record.confirmation_deadline = None
    record.save(update_fields=['confirmation_deadline'])
    initialize_confirmation_expiry()
    record.refresh_from_db()
    assert timezone.now() + timedelta(seconds=290) < record.confirmation_deadline
    scheduled = Schedule.objects.get(name='cmp-expire-confirmations')
    assert scheduled.func == 'cmp.confirmation.expire_due_confirmations'
    assert scheduled.schedule_type == Schedule.MINUTES
    assert scheduled.minutes == 1
    assert scheduled.repeats == -1
    original_deadline = record.confirmation_deadline
    original_next_run = scheduled.next_run
    initialize_confirmation_expiry()
    record.refresh_from_db()
    scheduled.refresh_from_db()
    assert record.confirmation_deadline == original_deadline
    assert scheduled.next_run == original_next_run


def test_setup_skips_partial_or_rolled_back_schema(pending_confirmation):
    record, _ = pending_confirmation
    record.confirmation_deadline = None
    record.save(update_fields=['confirmation_deadline'])
    with patch.object(connection.introspection, 'get_table_description', return_value=[]):
        initialize_confirmation_expiry()
    record.refresh_from_db()
    assert record.confirmation_deadline is None


@pytest.mark.parametrize('implicit', [False, True])
def test_response_advertises_deadline_only_for_explicit_confirmation(pending_confirmation, implicit):
    record, context = pending_confirmation
    context.cmp_transaction = record
    context.implicit_confirm = implicit
    context.cmp_shared_secret = 'test-only'
    message = rfc4210.PKIMessage()
    message['header']['pvno'] = 2
    message['header']['sender']['rfc822Name'] = 'ca@example.test'
    message['header']['recipient']['rfc822Name'] = 'device@example.test'
    message['body']['pkiconf'] = message['body']['pkiconf'].clone('')
    with patch.object(
        CmpMessageResponder, '_add_protection_shared_secret', side_effect=lambda pki_message, **_: pki_message
    ):
        CmpMessageResponder._protect_and_respond(message, context)
    parsed, remainder = decoder.decode(context.http_response_content, asn1Spec=rfc4210.PKIMessage())
    assert not remainder
    entries = {str(item['infoType']): item for item in parsed['header']['generalInfo']}
    assert ('1.3.6.1.5.5.7.4.14' in entries) is not implicit
    if not implicit:
        deadline, _ = decoder.decode(entries['1.3.6.1.5.5.7.4.14']['infoValue'].asOctets())
        assert str(deadline) == record.confirmation_deadline.strftime('%Y%m%d%H%M%SZ')
        assert parsed['header']['messageTime'].hasValue()


@pytest.mark.parametrize(('timeout', 'policy'), [(0, 'revoke'), (-1, 'log'), (300, 'invalid')])
def test_invalid_configuration_cannot_start_confirmation(pending_confirmation, settings, timeout, policy):
    record, context = pending_confirmation
    record.confirmation_deadline = None
    record.save(update_fields=['confirmation_deadline'])
    settings.TRUSTPOINT_CMP_CONFIRMATION_TIMEOUT_SECONDS = timeout
    settings.TRUSTPOINT_CMP_CONFIRMATION_TIMEOUT_POLICY = policy
    with pytest.raises(ImproperlyConfigured):
        CmpTransactionState.mark_issued(record.pk, context)
