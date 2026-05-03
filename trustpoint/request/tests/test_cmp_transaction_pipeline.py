"""Focused tests for CMP transaction persistence and polling integration."""

from __future__ import annotations

from unittest.mock import Mock

import pytest

from cmp.models import CmpTransactionModel
from devices.models import DeviceModel
from request.authorization.cmp import CmpPollAuthorization
from request.cmp_transaction_state import CmpTransactionState
from request.operation_processor.cmp_certificate_request import CmpCertificateRequestProcessor
from request.request_context import CmpCertificateRequestContext, CmpPollRequestContext
from workflows2.events.request_events import Events
from workflows2.models import Workflow2Approval, Workflow2Definition, Workflow2Instance, Workflow2Run
from workflows2.services.dispatch import DispatchOutcome


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
def test_cmp_transaction_state_syncs_rejected_approval_even_when_run_status_is_succeeded() -> None:
    """A rejected approval must reject the CMP transaction even if the run itself ended succeeded."""
    run = Workflow2Run.objects.create(
        trigger_on='cmp.certification',
        event_json={'x': 1},
        source_json={'trustpoint': True},
        status=Workflow2Run.STATUS_SUCCEEDED,
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
        status=Workflow2Instance.STATUS_SUCCEEDED,
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
