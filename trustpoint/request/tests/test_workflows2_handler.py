from unittest.mock import Mock, patch

import pytest

from request.request_context import (
    BaseRequestContext,
    CmpCertificateRequestContext,
    EstCertificateRequestContext,
    RestCertificateRequestContext,
)
from request.workflows2_handler import Workflow2HandleResult, Workflow2Handler
from workflows2.events.request_events import Events
from workflows2.events.triggers import Triggers
from workflows2.models import Workflow2Run
from workflows2.services.dispatch import DispatchOutcome


@pytest.mark.django_db
def test_workflows2_handler_continues_without_event() -> None:
    context = BaseRequestContext(protocol='est', operation='simpleenroll')

    result = Workflow2Handler().handle(context)

    assert result == Workflow2HandleResult.continue_processing()


@pytest.mark.django_db
def test_workflows2_handler_continues_when_no_definition_matches(test_csr_fixture) -> None:
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

    with patch('request.workflows2_handler.WorkflowDispatchService') as mock_service:
        mock_service.return_value.emit_event_outcome.return_value = None

        result = Workflow2Handler().handle(context)

    assert result == Workflow2HandleResult.continue_processing()
    assert context.workflow2_outcome is None


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
    assert context.workflow2_outcome == outcome
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
    assert context.workflow2_outcome == outcome


@pytest.mark.django_db
def test_workflows2_handler_emits_est_simplereenroll_from_request_context(test_csr_fixture) -> None:
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
        event=Events.est_simplereenroll,
        protocol='est',
        operation='simplereenroll',
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
    call = mock_service.return_value.emit_event_outcome.call_args.kwargs
    assert call['on'] == Triggers.EST_SIMPLEREENROLL
    assert call['event']['est']['operation'] == 'simplereenroll'
    assert context.workflow2_outcome == outcome


@pytest.mark.django_db
def test_workflows2_handler_emits_rest_enroll_from_request_context(test_csr_fixture) -> None:
    device = Mock()
    device.id = 'device-1'
    device.common_name = 'Device 1'
    device.serial_number = 'SER-1'

    issuing_ca = Mock()
    issuing_ca.id = 11

    domain = Mock()
    domain.id = 7
    domain.get_issuing_ca_or_value_error.return_value = issuing_ca

    context = RestCertificateRequestContext(
        event=Events.rest_enroll,
        protocol='rest',
        operation='enroll',
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
    call = mock_service.return_value.emit_event_outcome.call_args.kwargs
    assert call['on'] == Triggers.REST_ENROLL
    assert call['event']['rest']['operation'] == 'enroll'
    assert context.workflow2_outcome == outcome


@pytest.mark.django_db
def test_workflows2_handler_emits_cmp_initialization_from_request_context() -> None:
    device = Mock()
    device.id = 'device-1'
    device.common_name = 'Device 1'
    device.serial_number = 'SER-1'

    issuing_ca = Mock()
    issuing_ca.id = 11

    domain = Mock()
    domain.id = 7
    domain.get_issuing_ca_or_value_error.return_value = issuing_ca

    raw_message = Mock()
    raw_message.body = b'cmp-ir-request'

    context = CmpCertificateRequestContext(
        event=Events.cmp_initialization,
        raw_message=raw_message,
        protocol='cmp',
        operation='initialization',
        cmp_transaction_id='A1B2C3',
        cert_profile_str='domain_credential',
        device=device,
        domain=domain,
    )

    run = Mock()
    run.status = Workflow2Run.STATUS_SUCCEEDED
    outcome = DispatchOutcome(status='completed', run=run, instances=[Mock()])

    with patch('request.workflows2_handler.WorkflowDispatchService') as mock_service:
        mock_service.return_value.emit_event_outcome.return_value = outcome

        result = Workflow2Handler().handle(context)

    assert result.mode == 'continue'
    call = mock_service.return_value.emit_event_outcome.call_args.kwargs
    assert call['on'] == Triggers.CMP_INITIALIZATION
    assert call['event']['cmp']['operation'] == 'initialization'
    assert call['event']['cmp']['transaction_id'] == 'a1b2c3'
    assert call['event']['cmp']['fingerprint']
    assert call['idempotency_key'] == 'a1b2c3'
    assert 'csr_pem' not in call['event']['cmp']
    assert context.workflow2_outcome == outcome


@pytest.mark.django_db
def test_workflows2_handler_emits_cmp_certification_from_request_context() -> None:
    device = Mock()
    device.id = 'device-1'
    device.common_name = 'Device 1'
    device.serial_number = 'SER-1'

    issuing_ca = Mock()
    issuing_ca.id = 11

    domain = Mock()
    domain.id = 7
    domain.get_issuing_ca_or_value_error.return_value = issuing_ca

    raw_message = Mock()
    raw_message.body = b'cmp-cr-request'

    context = CmpCertificateRequestContext(
        event=Events.cmp_certification,
        raw_message=raw_message,
        protocol='cmp',
        operation='certification',
        cmp_transaction_id='D4E5F6',
        cert_profile_str='tls_client',
        device=device,
        domain=domain,
    )

    run = Mock()
    run.status = Workflow2Run.STATUS_SUCCEEDED
    outcome = DispatchOutcome(status='completed', run=run, instances=[Mock()])

    with patch('request.workflows2_handler.WorkflowDispatchService') as mock_service:
        mock_service.return_value.emit_event_outcome.return_value = outcome

        result = Workflow2Handler().handle(context)

    assert result.mode == 'continue'
    call = mock_service.return_value.emit_event_outcome.call_args.kwargs
    assert call['on'] == Triggers.CMP_CERTIFICATION
    assert call['event']['cmp']['operation'] == 'certification'
    assert call['event']['cmp']['transaction_id'] == 'd4e5f6'
    assert call['event']['cmp']['fingerprint']
    assert call['idempotency_key'] == 'd4e5f6'
    assert context.workflow2_outcome == outcome


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


@pytest.mark.django_db
def test_workflows2_handler_emits_device_updated_from_request_context() -> None:
    device = Mock()
    device.id = 'device-1'
    device.common_name = 'Device 1'
    device.serial_number = 'SER-1'
    device.domain_id = 9

    issuing_ca = Mock()
    issuing_ca.id = 11

    domain = Mock()
    domain.id = 9
    domain.get_issuing_ca_or_value_error.return_value = issuing_ca

    context = BaseRequestContext(
        event=Events.device_updated,
        event_payload={
            'device': {
                'id': 'device-1',
                'common_name': 'Device 1',
                'serial_number': 'SER-1',
                'domain_id': 9,
                'before': {'domain_id': 4},
                'after': {'domain_id': 9},
                'changes': {'domain_id': {'before': 4, 'after': 9}},
            },
        },
        device=device,
        domain=domain,
        protocol='device',
        operation='updated',
    )

    run = Mock()
    run.status = Workflow2Run.STATUS_SUCCEEDED
    outcome = DispatchOutcome(status='completed', run=run, instances=[Mock()])

    with patch('request.workflows2_handler.WorkflowDispatchService') as mock_service:
        mock_service.return_value.emit_event_outcome.return_value = outcome

        result = Workflow2Handler().handle(context)

    assert result.mode == 'continue'
    call = mock_service.return_value.emit_event_outcome.call_args.kwargs
    assert call['on'] == Triggers.DEVICE_UPDATED
    assert call['event']['device']['before']['domain_id'] == 4
    assert call['event']['device']['after']['domain_id'] == 9
    assert call['event']['device']['changes']['domain_id']['before'] == 4
    assert call['event']['device']['changes']['domain_id']['after'] == 9
    assert call['source'].ca_id == 11


@pytest.mark.django_db
def test_workflows2_handler_emits_device_deleted_from_request_context() -> None:
    device = Mock()
    device.id = 'device-1'
    device.common_name = 'Device 1'
    device.serial_number = 'SER-1'
    device.domain_id = 9

    issuing_ca = Mock()
    issuing_ca.id = 11

    domain = Mock()
    domain.id = 9
    domain.get_issuing_ca_or_value_error.return_value = issuing_ca

    context = BaseRequestContext(
        event=Events.device_deleted,
        device=device,
        domain=domain,
        protocol='device',
        operation='deleted',
    )

    run = Mock()
    run.status = Workflow2Run.STATUS_SUCCEEDED
    outcome = DispatchOutcome(status='completed', run=run, instances=[Mock()])

    with patch('request.workflows2_handler.WorkflowDispatchService') as mock_service:
        mock_service.return_value.emit_event_outcome.return_value = outcome

        result = Workflow2Handler().handle(context)

    assert result.mode == 'continue'
    call = mock_service.return_value.emit_event_outcome.call_args.kwargs
    assert call['on'] == Triggers.DEVICE_DELETED
    assert call['event']['device']['domain_id'] == 9
    assert call['source'].ca_id == 11
