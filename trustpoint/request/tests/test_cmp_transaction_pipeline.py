"""Focused tests for CMP transaction persistence and polling integration."""

from __future__ import annotations

from unittest.mock import Mock, patch

import pytest

from cmp.models import CmpTransactionModel
from request.authorization.cmp import CmpPollAuthorization
from request.operation_processor.cmp_enrollment_request import CmpEnrollmentRequestProcessor
from request.request_context import CmpCertificateRequestContext, CmpPollRequestContext
from workflows2.events.request_events import Events
from workflows2.models import Workflow2Run
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
        operation='polling',
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
def test_cmp_enrollment_request_processor_persists_waiting_transaction_for_pending_workflow() -> None:
    """CMP enrollment should persist a waiting CMP transaction when workflows2 delays issuance."""
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

    def _handle_workflow(ctx: CmpCertificateRequestContext) -> None:
        ctx.workflow2_outcome = outcome

    with patch(
        'request.operation_processor.cmp_enrollment_request.Workflow2Handler.handle',
        side_effect=_handle_workflow,
    ):
        CmpEnrollmentRequestProcessor().process_operation(context)

    transaction_record = CmpTransactionModel.objects.get(transaction_id='feedface')
    assert transaction_record.status == CmpTransactionModel.Status.WAITING
    assert transaction_record.backend == CmpTransactionModel.Backend.WORKFLOW2
    assert transaction_record.backend_reference == 'run-1'
    assert transaction_record.request_body_type == 'ir'
    assert transaction_record.operation == 'initialization'
    assert context.cmp_transaction == transaction_record
