# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Focused tests for CMP transaction persistence and polling integration."""

from __future__ import annotations

from unittest.mock import Mock, patch

import pytest

from cmp.models import CmpTransactionModel
from devices.models import DeviceModel
from request.authorization.cmp import CmpPollAuthorization
from request.cmp_transaction_state import CmpTransactionState
from request.operation_processor.cmp_certificate_request import CmpCertificateRequestProcessor
from request.operation_processor.cmp_poll import CmpPollProcessor
from request.request_context import CmpCertificateRequestContext, CmpPollRequestContext
from workflows2.events.request_events import Events
from workflows2.models import Workflow2Approval, Workflow2Definition, Workflow2Instance, Workflow2Run
from workflows2.services.dispatch import DispatchOutcome
from request.workflow2_issuance import Workflow2IssuanceDecision
from workflows2.services.request_decision import Workflow2RequestDecision


@pytest.mark.django_db
def test_cmp_poll_authorization_infers_operation_from_transaction() -> None:
    """PollReq authorization should resolve the original CMP operation from the stored transaction."""
    transaction_record = CmpTransactionModel.objects.create(
        transaction_id='deadbeef',
        operation='initialization',
        request_body_type='ir',
        domain_name='test-domain',
        cert_profile='domain_credential',
        cert_req_id=0,
        request_der=b'cmp-ir-request',
        implicit_confirm=True,
        status=CmpTransactionModel.Status.WAITING,
        detail='Enrollment request pending workflow approval.',
        check_after_seconds=5,
    )

    context = CmpPollRequestContext(
        protocol='cmp',
        cmp_body_type='pollReq',
        cmp_transaction_id='deadbeef',
        poll_cert_req_id=0,
    )

    CmpPollAuthorization().authorize(context)

    assert context.operation == 'initialization'
    assert context.cert_profile_str == 'domain_credential'
    assert context.implicit_confirm is True
    assert context.cmp_transaction == transaction_record


@pytest.mark.django_db
@pytest.mark.parametrize(
    ('decision', 'status'),
    [
        (Workflow2IssuanceDecision.REJECT, CmpTransactionModel.Status.REJECTED),
        (Workflow2IssuanceDecision.FAIL, CmpTransactionModel.Status.FAILED),
    ],
)
def test_cmp_certificate_request_processor_persists_terminal_workflow_outcomes(decision, status) -> None:
    context = CmpCertificateRequestContext(
        raw_message=Mock(body=b'cmp-ir-request'), protocol='cmp', operation='initialization',
        domain_str='test-domain', cmp_body_type='ir', cmp_transaction_id='terminal-id',
    )
    run = Mock(id='run-terminal', status=Workflow2Run.STATUS_FINISHED)
    context.workflow2_outcome = DispatchOutcome(status='terminal', run=run, instances=[])

    with patch('request.operation_processor.cmp_certificate_request.get_workflow2_issuance_decision', return_value=decision):
        CmpCertificateRequestProcessor().process_operation(context)

    assert context.cmp_transaction.status == status


@pytest.mark.django_db
def test_cmp_certificate_request_processor_rejects_missing_transaction_or_body() -> None:
    processor = CmpCertificateRequestProcessor()
    with pytest.raises(TypeError, match='requires a CmpCertificateRequestContext'):
        processor.process_operation(Mock())
    with pytest.raises(ValueError, match='missing transactionID'):
        processor.process_operation(CmpCertificateRequestContext(protocol='cmp', cmp_body_type='ir'))
    context = CmpCertificateRequestContext(
        protocol='cmp', cmp_body_type='ir', cmp_transaction_id='missing-body', raw_message=Mock(body=b''),
    )
    with pytest.raises(ValueError, match='body is empty'):
        processor.process_operation(context)


def test_cmp_certificate_request_processor_rejects_missing_waiting_outcome() -> None:
    """A waiting decision must carry the workflow run needed for polling."""
    context = CmpCertificateRequestContext(
        raw_message=Mock(body=bytearray(b'cmp-ir-request')), protocol='cmp', operation='initialization',
        cmp_body_type='ir', cmp_transaction_id='missing-outcome',
    )

    with patch(
        'request.operation_processor.cmp_certificate_request.get_workflow2_issuance_decision',
        return_value=Workflow2IssuanceDecision.WAIT,
    ), pytest.raises(ValueError, match='requires a Workflow 2 outcome'):
        CmpCertificateRequestProcessor().process_operation(context)


def test_cmp_request_helpers_normalize_supported_body_values() -> None:
    """Normalize bytearray and text HTTP bodies and reject unsupported values."""
    processor = CmpCertificateRequestProcessor()
    context = CmpCertificateRequestContext(raw_message=Mock(body=bytearray(b'bytes')))
    assert processor._request_body_bytes(context) == b'bytes'  # noqa: SLF001
    context.raw_message.body = 'text'
    assert processor._request_body_bytes(context) == b'text'  # noqa: SLF001
    context.raw_message.body = object()
    with pytest.raises(TypeError, match='must be bytes-like'):
        processor._request_body_bytes(context)  # noqa: SLF001


def test_cmp_request_helpers_reject_missing_http_message_and_empty_transaction_id() -> None:
    processor = CmpCertificateRequestProcessor()
    with pytest.raises(ValueError, match='missing its raw HTTP message'):
        processor._request_body_bytes(CmpCertificateRequestContext())  # noqa: SLF001
    with pytest.raises(ValueError, match='body is empty'):
        processor._require_request_der(CmpCertificateRequestContext(raw_message=Mock(body=b'')))  # noqa: SLF001
    with pytest.raises(ValueError, match='missing transactionID'):
        processor._require_transaction_id(CmpCertificateRequestContext(cmp_transaction_id='  '))  # noqa: SLF001


def test_cmp_pending_detail_distinguishes_awaiting_and_processing_runs() -> None:
    processor = CmpCertificateRequestProcessor()
    assert 'approval' in processor.detail_for_pending_run(Workflow2Run.STATUS_AWAITING)
    assert 'processing' in processor.detail_for_pending_run(Workflow2Run.STATUS_RUNNING)


@pytest.mark.django_db
def test_cmp_certificate_request_processor_rejects_transaction_reuse() -> None:
    CmpTransactionModel.objects.create(
        transaction_id='reused', operation='initialization', request_body_type='ir', request_der=b'original',
        status=CmpTransactionModel.Status.WAITING,
    )
    context = CmpCertificateRequestContext(
        raw_message=Mock(body=b'different'), protocol='cmp', operation='initialization',
        cmp_body_type='ir', cmp_transaction_id='REUSED',
    )

    with pytest.raises(ValueError, match='already in use'):
        CmpCertificateRequestProcessor().process_operation(context)


@pytest.mark.django_db
def test_cmp_certificate_request_processor_hydrates_existing_issued_transaction() -> None:
    transaction_record = CmpTransactionModel.objects.create(
        transaction_id='issued-replay', operation='initialization', request_body_type='ir',
        request_der=b'issued-request', status=CmpTransactionModel.Status.ISSUED,
        implicit_confirm=True, cert_profile='domain_credential',
    )
    context = CmpCertificateRequestContext(
        raw_message=Mock(body=b'issued-request'), protocol='cmp', operation='initialization',
        cmp_body_type='ir', cmp_transaction_id='issued-replay',
    )

    with patch.object(CmpCertificateRequestProcessor, 'populate_success_context') as populate:
        CmpCertificateRequestProcessor().process_operation(context)

    assert context.cmp_transaction == transaction_record
    populate.assert_called_once_with(context, transaction_record)


def test_cmp_certificate_request_processor_delegates_wrong_context_protocol_and_operation() -> None:
    processor = CmpCertificateRequestProcessor()
    with patch('request.operation_processor.cmp_certificate_request.CertificateIssueProcessor.process_operation') as issue:
        processor.process_operation(CmpCertificateRequestContext(protocol='est'))
        processor.process_operation(CmpCertificateRequestContext(protocol='cmp', cmp_body_type='pollReq'))
    assert issue.call_count == 2


@pytest.mark.django_db
def test_cmp_certificate_request_processor_persists_waiting_transaction_for_pending_workflow() -> None:
    """CMP certificate requests should persist a waiting transaction when workflows2 delays issuance."""
    raw_message = Mock()
    raw_message.body = b'cmp-ir-request'

    context = CmpCertificateRequestContext(
        raw_message=raw_message,
        protocol='cmp',
        operation='initialization',
        domain_str='test-domain',
        cert_profile_str='domain_credential',
        cmp_body_type='ir',
        cmp_transaction_id='feedface',
        event=Events.cmp_initialization,
    )

    run = Mock()
    run.id = 'run-1'
    run.status = Workflow2Run.STATUS_AWAITING
    outcome = DispatchOutcome(status='blocked', run=run, instances=[Mock()])
    context.workflow2_outcome = outcome

    CmpCertificateRequestProcessor().process_operation(context)

    transaction_record = CmpTransactionModel.objects.get(transaction_id='feedface')
    assert transaction_record.status == CmpTransactionModel.Status.WAITING
    assert transaction_record.backend == CmpTransactionModel.Backend.WORKFLOW2
    assert transaction_record.backend_reference == 'run-1'
    assert transaction_record.request_body_type == 'ir'
    assert transaction_record.operation == 'initialization'
    assert context.cmp_transaction == transaction_record


@pytest.mark.django_db
@pytest.mark.parametrize('issue_side_effect', [RuntimeError('issue failed'), None])
def test_cmp_certificate_request_processor_persists_failed_issuance_outcome(issue_side_effect: Exception | None) -> None:
    context = CmpCertificateRequestContext(
        raw_message=Mock(body=b'cmp-ir-request'), protocol='cmp', operation='initialization',
        domain_str='test-domain', cmp_body_type='ir', cmp_transaction_id=f'issue-{issue_side_effect is None}',
    )
    with patch(
        'request.operation_processor.cmp_certificate_request.CertificateIssueProcessor.process_operation',
        side_effect=issue_side_effect,
    ) as issue:
        if issue_side_effect is not None:
            with pytest.raises(RuntimeError, match='issue failed'):
                CmpCertificateRequestProcessor().process_operation(context)
        else:
            CmpCertificateRequestProcessor().process_operation(context)

    transaction_record = CmpTransactionModel.objects.get(transaction_id=context.cmp_transaction.transaction_id)
    assert transaction_record.status == CmpTransactionModel.Status.FAILED
    assert 'failed while issuing' in transaction_record.detail or 'without issuing' in transaction_record.detail
    issue.assert_called_once_with(context)


@pytest.mark.django_db
def test_cmp_transaction_state_syncs_cancelled_workflow_runs() -> None:
    """Cancelling a workflows2 run should release waiting CMP transactions."""
    device = DeviceModel.objects.create(common_name='cmp-device', serial_number='cmp-serial')
    run = Workflow2Run.objects.create(
        trigger_on='cmp.initialization',
        event_json={'x': 1},
        source_json={'trustpoint': True},
        status=Workflow2Run.STATUS_CANCELLED,
        finalized=True,
    )
    transaction_record = CmpTransactionModel.objects.create(
        transaction_id='deadcafe',
        operation='initialization',
        request_body_type='ir',
        domain_name='test-domain',
        cert_profile='domain_credential',
        cert_req_id=0,
        request_der=b'cmp-ir-request',
        device=device,
        status=CmpTransactionModel.Status.WAITING,
        backend=CmpTransactionModel.Backend.WORKFLOW2,
        backend_reference=str(run.id),
    )

    CmpTransactionState.sync_from_workflow2_run(run=run)

    transaction_record.refresh_from_db()
    assert transaction_record.status == CmpTransactionModel.Status.CANCELLED
    assert transaction_record.backend == CmpTransactionModel.Backend.NONE
    assert transaction_record.backend_reference == str(run.id)
    assert transaction_record.device is None


@pytest.mark.django_db
def test_cmp_transaction_state_syncs_rejected_approval_even_when_run_status_is_finished() -> None:
    """A rejected approval must reject the CMP transaction even if the run itself ended finished."""
    run = Workflow2Run.objects.create(
        trigger_on='cmp.certification',
        event_json={'x': 1},
        source_json={'trustpoint': True},
        status=Workflow2Run.STATUS_FINISHED,
        finalized=True,
    )
    definition = Workflow2Definition.objects.create(
        name='cmp-certification-definition',
        enabled=True,
        trigger_on='cmp.certification',
        yaml_text='schema: trustpoint.workflow.v2',
        ir_json={},
        ir_hash='cmp-certification-hash',
    )
    instance = Workflow2Instance.objects.create(
        run=run,
        definition=definition,
        event_json={'x': 1},
        vars_json={},
        status=Workflow2Instance.STATUS_FINISHED,
    )
    Workflow2Approval.objects.create(
        instance=instance,
        step_id='approve',
        status=Workflow2Approval.STATUS_REJECTED,
    )
    transaction_record = CmpTransactionModel.objects.create(
        transaction_id='00112233445566778899aabbccddeeff',
        operation='certification',
        request_body_type='cr',
        domain_name='test-domain',
        cert_profile='tls_client',
        cert_req_id=0,
        request_der=b'cmp-cr-request',
        status=CmpTransactionModel.Status.WAITING,
        backend=CmpTransactionModel.Backend.WORKFLOW2,
        backend_reference=str(run.id),
    )

    CmpTransactionState.sync_from_workflow2_run(run=run)

    transaction_record.refresh_from_db()
    assert transaction_record.status == CmpTransactionModel.Status.REJECTED


@pytest.mark.django_db
@pytest.mark.parametrize(
    ('decision', 'run_status', 'expected_status', 'detail'),
    [
        (Workflow2RequestDecision.CONTINUE, Workflow2Run.STATUS_RUNNING, CmpTransactionModel.Status.PROCESSING,
         'CMP poll finalization in progress.'),
        (Workflow2RequestDecision.WAIT, Workflow2Run.STATUS_AWAITING, CmpTransactionModel.Status.WAITING,
         'Enrollment request pending workflow approval.'),
    ],
)
def test_cmp_transaction_state_syncs_pending_workflow_decisions(
    decision: Workflow2RequestDecision,
    run_status: str,
    expected_status: str,
    detail: str,
) -> None:
    """Synchronize waiting transactions to processing or waiting state."""
    run = Workflow2Run.objects.create(
        trigger_on='cmp.initialization', event_json={}, source_json={}, status=run_status,
    )
    transaction_record = CmpTransactionModel.objects.create(
        transaction_id=f'sync-{decision.value}', operation='initialization', request_body_type='ir',
        request_der=b'cmp-request', status=CmpTransactionModel.Status.WAITING,
        backend=CmpTransactionModel.Backend.WORKFLOW2, backend_reference=str(run.pk), check_after_seconds=9,
    )

    with patch('request.cmp_transaction_state.resolve_request_decision', return_value=decision):
        CmpTransactionState.sync_from_workflow2_run(run=run)

    transaction_record.refresh_from_db()
    assert transaction_record.status == expected_status
    assert transaction_record.detail == detail


@pytest.mark.django_db
@pytest.mark.parametrize(
    ('decision', 'run_status', 'expected_status'),
    [
        (Workflow2RequestDecision.WAIT, Workflow2Run.STATUS_AWAITING, CmpTransactionModel.Status.WAITING),
        (Workflow2RequestDecision.CONTINUE, Workflow2Run.STATUS_RUNNING, CmpTransactionModel.Status.PROCESSING),
        (Workflow2RequestDecision.REJECT, Workflow2Run.STATUS_FINISHED, CmpTransactionModel.Status.REJECTED),
        (Workflow2RequestDecision.FAIL, Workflow2Run.STATUS_ERROR, CmpTransactionModel.Status.FAILED),
    ],
)
def test_cmp_poll_refreshes_waiting_transaction_for_each_workflow_decision(
    decision: Workflow2RequestDecision,
    run_status: str,
    expected_status: str,
) -> None:
    """Refresh a waiting transaction for each workflow request decision."""
    run = Workflow2Run.objects.create(
        trigger_on='cmp.initialization', event_json={}, source_json={}, status=run_status,
    )
    transaction_record = CmpTransactionModel.objects.create(
        transaction_id=f'poll-{decision.value}', operation='initialization', request_body_type='ir',
        request_der=b'cmp-request', status=CmpTransactionModel.Status.WAITING,
        backend=CmpTransactionModel.Backend.WORKFLOW2, backend_reference=str(run.pk),
        check_after_seconds=12,
    )
    context = CmpPollRequestContext(cmp_transaction=transaction_record)

    finalize_patch = (
        patch.object(CmpPollProcessor, '_finalize_transaction')
        if decision == Workflow2RequestDecision.CONTINUE
        else patch.object(CmpPollProcessor, '_finalize_transaction', autospec=True)
    )
    with patch('request.operation_processor.cmp_poll.resolve_request_decision', return_value=decision), finalize_patch:
        CmpPollProcessor().process_operation(context)

    transaction_record.refresh_from_db()
    assert transaction_record.status == expected_status
    assert context.cmp_transaction == transaction_record
    if decision == Workflow2RequestDecision.WAIT:
        assert transaction_record.detail == 'Enrollment request pending workflow approval.'
    elif decision == Workflow2RequestDecision.CONTINUE:
        assert transaction_record.detail == 'CMP poll finalization in progress.'


@pytest.mark.django_db
@pytest.mark.parametrize('backend_reference', ['', '00000000-0000-0000-0000-000000000001'])
def test_cmp_poll_marks_missing_workflow_reference_failed(backend_reference: str) -> None:
    """Persist a failure when a waiting transaction cannot find its backend run."""
    transaction_record = CmpTransactionModel.objects.create(
        transaction_id=f'missing-{backend_reference or "empty"}', operation='initialization', request_body_type='ir',
        request_der=b'cmp-request', status=CmpTransactionModel.Status.WAITING,
        backend=CmpTransactionModel.Backend.WORKFLOW2, backend_reference=backend_reference,
    )
    context = CmpPollRequestContext(cmp_transaction=transaction_record)

    CmpPollProcessor().process_operation(context)

    transaction_record.refresh_from_db()
    assert transaction_record.status == CmpTransactionModel.Status.FAILED
    assert transaction_record.finalized_at is not None
    assert 'run reference' in transaction_record.detail or 'no longer exists' in transaction_record.detail


@pytest.mark.django_db
@pytest.mark.parametrize('issue_result', ['exception', 'no-certificate'])
def test_cmp_poll_finalization_failures_are_persisted(issue_result: str) -> None:
    """Persist poll finalization exceptions and missing certificate results."""
    transaction_record = CmpTransactionModel.objects.create(
        transaction_id=f'finalize-{issue_result}', operation='initialization', request_body_type='ir',
        request_der=b'cmp-request', status=CmpTransactionModel.Status.PROCESSING,
    )
    context = CmpPollRequestContext(cmp_transaction=transaction_record)
    replay_context = Mock(issued_certificate=None)
    issue_patch = patch(
        'request.operation_processor.cmp_poll.CertificateIssueProcessor.process_operation',
        side_effect=RuntimeError('issuer failed') if issue_result == 'exception' else None,
    )
    with patch.object(CmpCertificateRequestProcessor, 'build_replay_context', return_value=replay_context), issue_patch:
        CmpPollProcessor().process_operation(context)

    transaction_record.refresh_from_db()
    assert transaction_record.status == CmpTransactionModel.Status.FAILED
    assert transaction_record.finalized_at is not None
    assert 'without issuing' in transaction_record.detail or 'failed while issuing' in transaction_record.detail


@pytest.mark.django_db
def test_cmp_poll_finalization_hydrates_successful_issuance() -> None:
    """Hydrate the poll context after the issuance boundary succeeds."""
    transaction_record = CmpTransactionModel.objects.create(
        transaction_id='finalize-success', operation='initialization', request_body_type='ir',
        request_der=b'cmp-request', status=CmpTransactionModel.Status.PROCESSING,
    )
    context = CmpPollRequestContext(cmp_transaction=transaction_record)
    replay_context = Mock(issued_certificate=Mock())
    issued_transaction = Mock(status=CmpTransactionModel.Status.ISSUED)

    with patch.object(CmpCertificateRequestProcessor, 'build_replay_context', return_value=replay_context), \
        patch('request.operation_processor.cmp_poll.CertificateIssueProcessor.process_operation'), \
        patch.object(CmpCertificateRequestProcessor, 'mark_transaction_issued', return_value=issued_transaction), \
        patch.object(CmpCertificateRequestProcessor, 'populate_success_context') as populate:
        CmpPollProcessor().process_operation(context)

    assert context.cmp_transaction is issued_transaction
    populate.assert_called_once_with(context, issued_transaction)
