"""Tests for request-level Workflow 2 delivery helpers."""

from __future__ import annotations

import pytest

from cmp.models import CmpTransactionModel
from request.request_context import CmpPollRequestContext, EstCertificateRequestContext
from request.workflow2_issuance import (
    Workflow2IssuanceDecision,
    get_workflow2_issuance_decision,
    release_delivered_workflow2_request,
)
from workflows2.models import Workflow2Approval, Workflow2Definition, Workflow2Instance, Workflow2Run
from workflows2.services.dispatch import DispatchOutcome


def _create_rejected_request_run(*, trigger_on: str) -> Workflow2Run:
    run = Workflow2Run.objects.create(
        trigger_on=trigger_on,
        event_json={'x': 1},
        source_json={'trustpoint': True},
        idempotency_key='same-request',
        status=Workflow2Run.STATUS_SUCCEEDED,
        finalized=True,
    )
    definition = Workflow2Definition.objects.create(
        name=f'{trigger_on}-definition',
        enabled=True,
        trigger_on=trigger_on,
        yaml_text='schema: trustpoint.workflow.v2',
        ir_json={},
        ir_hash=f'hash-{trigger_on}',
    )
    instance = Workflow2Instance.objects.create(
        run=run,
        definition=definition,
        event_json={'x': 1},
        vars_json={},
        status=Workflow2Instance.STATUS_SUCCEEDED,
    )
    Workflow2Approval.objects.create(
        instance=instance,
        step_id='approve',
        status=Workflow2Approval.STATUS_REJECTED,
    )
    return run


@pytest.mark.django_db
def test_release_delivered_workflow2_request_releases_successful_est_run() -> None:
    """A successful EST delivery should release the run idempotency key for future requests."""
    run = Workflow2Run.objects.create(
        trigger_on='est.simpleenroll',
        event_json={'x': 1},
        source_json={'trustpoint': True},
        idempotency_key='same-request',
        status=Workflow2Run.STATUS_SUCCEEDED,
        finalized=True,
    )
    context = EstCertificateRequestContext(protocol='est', operation='simpleenroll')
    context.workflow2_outcome = DispatchOutcome(status='completed', run=run, instances=[])

    release_delivered_workflow2_request(context)

    run.refresh_from_db()
    assert run.idempotency_key == ''


@pytest.mark.django_db
def test_release_delivered_workflow2_request_keeps_pending_est_run() -> None:
    """A pending EST response must keep its idempotency key so retries reuse the same run."""
    run = Workflow2Run.objects.create(
        trigger_on='est.simpleenroll',
        event_json={'x': 1},
        source_json={'trustpoint': True},
        idempotency_key='same-request',
        status=Workflow2Run.STATUS_AWAITING,
        finalized=False,
    )
    context = EstCertificateRequestContext(protocol='est', operation='simpleenroll')
    context.workflow2_outcome = DispatchOutcome(status='blocked', run=run, instances=[])

    release_delivered_workflow2_request(context)

    run.refresh_from_db()
    assert run.idempotency_key == 'same-request'


@pytest.mark.django_db
def test_release_delivered_workflow2_request_keeps_rejected_est_run() -> None:
    """A rejected EST response must keep its idempotency key so retries replay the rejection."""
    run = Workflow2Run.objects.create(
        trigger_on='est.simpleenroll',
        event_json={'x': 1},
        source_json={'trustpoint': True},
        idempotency_key='same-request',
        status=Workflow2Run.STATUS_REJECTED,
        finalized=True,
    )
    context = EstCertificateRequestContext(protocol='est', operation='simpleenroll')
    context.workflow2_outcome = DispatchOutcome(status='completed', run=run, instances=[])

    release_delivered_workflow2_request(context)

    run.refresh_from_db()
    assert run.idempotency_key == 'same-request'


@pytest.mark.django_db
def test_rejected_approval_branch_keeps_succeeded_est_run_rejected_for_requests() -> None:
    """A rejected approval must stay rejected even when the workflow run later ends succeeded."""
    run = _create_rejected_request_run(trigger_on='est.simpleenroll')
    context = EstCertificateRequestContext(protocol='est', operation='simpleenroll')
    context.workflow2_outcome = DispatchOutcome(status='completed', run=run, instances=[])

    assert get_workflow2_issuance_decision(context) == Workflow2IssuanceDecision.REJECT

    release_delivered_workflow2_request(context)

    run.refresh_from_db()
    assert run.idempotency_key == 'same-request'


@pytest.mark.django_db
def test_release_delivered_workflow2_request_releases_cmp_terminal_run() -> None:
    """A final CMP delivery should release the underlying workflows2 run key."""
    run = Workflow2Run.objects.create(
        trigger_on='cmp.certification',
        event_json={'x': 1},
        source_json={'trustpoint': True},
        idempotency_key='same-request',
        status=Workflow2Run.STATUS_SUCCEEDED,
        finalized=True,
    )
    transaction = CmpTransactionModel.objects.create(
        transaction_id='deadbeefdeadbeefdeadbeefdeadbeef',
        operation='certification',
        request_body_type='cr',
        domain_name='test-domain',
        cert_profile='tls_client',
        cert_req_id=0,
        request_der=b'cmp-cr-request',
        status=CmpTransactionModel.Status.ISSUED,
        backend=CmpTransactionModel.Backend.WORKFLOW2,
        backend_reference=str(run.id),
    )
    context = CmpPollRequestContext(protocol='cmp', cmp_body_type='pollReq')
    context.cmp_transaction = transaction
    context.http_response_content_type = 'application/pkixcmp'

    release_delivered_workflow2_request(context)

    run.refresh_from_db()
    assert run.idempotency_key == ''


@pytest.mark.django_db
def test_release_delivered_workflow2_request_keeps_cmp_rejection_run() -> None:
    """A CMP rejection delivery must keep the workflow run bound to that rejected request."""
    run = Workflow2Run.objects.create(
        trigger_on='cmp.certification',
        event_json={'x': 1},
        source_json={'trustpoint': True},
        idempotency_key='same-request',
        status=Workflow2Run.STATUS_REJECTED,
        finalized=True,
    )
    transaction = CmpTransactionModel.objects.create(
        transaction_id='feedbeeffeedbeeffeedbeeffeedbeef',
        operation='certification',
        request_body_type='cr',
        domain_name='test-domain',
        cert_profile='tls_client',
        cert_req_id=0,
        request_der=b'cmp-cr-request',
        status=CmpTransactionModel.Status.REJECTED,
        backend=CmpTransactionModel.Backend.WORKFLOW2,
        backend_reference=str(run.id),
    )
    context = CmpPollRequestContext(protocol='cmp', cmp_body_type='pollReq')
    context.cmp_transaction = transaction
    context.http_response_content_type = 'application/pkixcmp'

    release_delivered_workflow2_request(context)

    run.refresh_from_db()
    assert run.idempotency_key == 'same-request'
