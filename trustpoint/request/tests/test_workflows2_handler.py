from unittest.mock import Mock, patch

import pytest

from request.request_context import BaseRequestContext, EstCertificateRequestContext
from request.workflows2_handler import Workflow2HandleResult, Workflow2Handler
from workflows.events import Events
from workflows2.events.triggers import Triggers
from workflows2.models import Workflow2Run
from workflows2.services.dispatch import DispatchOutcome


@pytest.mark.django_db
def test_workflows2_handler_returns_no_match_without_event() -> None:
    context = BaseRequestContext(protocol='est', operation='simpleenroll')

    result = Workflow2Handler().handle(context)

    assert result == Workflow2HandleResult.no_match()


@pytest.mark.django_db
def test_workflows2_handler_blocks_est_simpleenroll_when_workflow_is_awaiting(test_csr_fixture) -> None:
    device = Mock()
    device.id = 'device-1'
    device.common_name = 'Device 1'
    device.serial_number = 'SER-1'

    issuing_ca = Mock()
    issuing_ca.id = 11

    domain = Mock()
    domain.id = 7
    domain.get_issuing_ca_or_value_error.return_value = issuing_ca

    context = EstCertificateRequestContext(
        event=Events.est_simpleenroll,
        protocol='est',
        operation='simpleenroll',
        cert_profile_str='tls_client',
        device=device,
        domain=domain,
        cert_requested=test_csr_fixture.get_cryptography_object(),
    )

    run = Mock()
    run.status = Workflow2Run.STATUS_AWAITING
    outcome = DispatchOutcome(status='blocked', run=run, instances=[])

    with patch('request.workflows2_handler.WorkflowDispatchService') as mock_service:
        mock_service.return_value.emit_event_outcome.return_value = outcome

        result = Workflow2Handler().handle(context)

    assert result.should_stop is True
    assert context.http_response_status == 202
    assert context.http_response_content == 'Enrollment request pending workflow approval.'
    mock_service.return_value.emit_event_outcome.assert_called_once()
    assert mock_service.return_value.emit_event_outcome.call_args.kwargs['on'] == Triggers.EST_SIMPLEENROLL


@pytest.mark.django_db
def test_workflows2_handler_marks_est_gate_applied_on_success(test_csr_fixture) -> None:
    device = Mock()
    device.id = 'device-1'
    device.common_name = 'Device 1'
    device.serial_number = 'SER-1'

    issuing_ca = Mock()
    issuing_ca.id = 11

    domain = Mock()
    domain.id = 7
    domain.get_issuing_ca_or_value_error.return_value = issuing_ca

    context = EstCertificateRequestContext(
        event=Events.est_simpleenroll,
        protocol='est',
        operation='simpleenroll',
        cert_profile_str='tls_client',
        device=device,
        domain=domain,
        cert_requested=test_csr_fixture.get_cryptography_object(),
    )

    run = Mock()
    run.status = Workflow2Run.STATUS_SUCCEEDED
    outcome = DispatchOutcome(status='completed', run=run, instances=[Mock()])

    with patch('request.workflows2_handler.WorkflowDispatchService') as mock_service:
        mock_service.return_value.emit_event_outcome.return_value = outcome

        result = Workflow2Handler().handle(context)

    assert result.mode == 'continue'
    assert getattr(context, 'workflow2_gate_applied', False) is True


@pytest.mark.django_db
def test_workflows2_handler_emits_device_created_from_request_context() -> None:
    device = Mock()
    device.id = 'device-1'
    device.common_name = 'Device 1'
    device.serial_number = 'SER-1'
    device.domain_id = 9

    context = BaseRequestContext(
        event=Events.device_created,
        device=device,
        protocol='device',
        operation='created',
    )

    run = Mock()
    run.status = Workflow2Run.STATUS_SUCCEEDED
    outcome = DispatchOutcome(status='completed', run=run, instances=[Mock()])

    with patch('request.workflows2_handler.WorkflowDispatchService') as mock_service:
        mock_service.return_value.emit_event_outcome.return_value = outcome

        result = Workflow2Handler().handle(context)

    assert result.mode == 'continue'
    call = mock_service.return_value.emit_event_outcome.call_args.kwargs
    assert call['on'] == Triggers.DEVICE_CREATED
    assert call['event']['device']['id'] == 'device-1'
    assert call['source'].trustpoint is True
