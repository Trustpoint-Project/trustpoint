# Copyright (c) 2025 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Tests for request/message_responder.py."""

import base64
import json
from typing import Any
from unittest.mock import Mock, patch

import pytest
from cryptography.hazmat.primitives.serialization import Encoding, pkcs7

from cmp.models import CmpTransactionModel
from onboarding.models import OnboardingStatus
from request.message_responder.cmp import (
    CmpErrorMessageResponder,
    CmpInitializationResponder,
    CmpMessageResponder,
    CmpPkiConfResponder,
    CmpTransactionResponder,
    _der_tlv,
)
from request.message_responder.est import (
    EstCertificateMessageResponder,
    EstErrorMessageResponder,
    EstMessageResponder,
)
from request.message_responder.rest import (
    RestCertificateMessageResponder,
    RestErrorMessageResponder,
    RestMessageResponder,
)
from request.request_context import (
    BaseRequestContext,
    CmpBaseRequestContext,
    CmpCertConfRequestContext,
    CmpCertificateRequestContext,
    CmpPollRequestContext,
    EstBaseRequestContext,
    EstCertificateRequestContext,
    RestBaseRequestContext,
    RestCertificateRequestContext,
)
from request.workflow2_issuance import Workflow2IssuanceDecision
from workflows2.models import Workflow2Approval, Workflow2Definition, Workflow2Instance, Workflow2Run
from workflows2.services.dispatch import DispatchOutcome


def _create_rejected_request_run(*, trigger_on: str) -> Workflow2Run:
    run = Workflow2Run.objects.create(
        trigger_on=trigger_on,
        event_json={'x': 1},
        source_json={'trustpoint': True},
        status=Workflow2Run.STATUS_FINISHED,
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
        status=Workflow2Instance.STATUS_FINISHED,
    )
    Workflow2Approval.objects.create(
        instance=instance,
        step_id='approve',
        status=Workflow2Approval.STATUS_REJECTED,
    )
    return run


@pytest.mark.django_db
class TestEstMessageResponder:
    """Tests for EstMessageResponder class."""

    def test_incorrect_context_type(self) -> None:
        context = Mock(spec=BaseRequestContext)

        with pytest.raises(TypeError, match='EstMessageResponder requires a subclass of EstBaseRequestContext.'):
            EstMessageResponder.build_response(context)

    def test_build_response_pending_workflow2_outcome(self) -> None:
        """Test build_response with a pending Workflow 2 run."""
        context = Mock(spec=EstCertificateRequestContext)
        run = Mock()
        run.status = Workflow2Run.STATUS_AWAITING
        context.workflow2_outcome = DispatchOutcome(status='blocked', run=run, instances=[Mock()])

        EstCertificateMessageResponder.build_response(context)

        assert context.http_response_status == 202
        assert context.http_response_content_type == 'text/plain'
        assert context.http_response_content == 'Enrollment request pending workflow approval.'

    def test_build_response_rejected_workflow2_outcome(self) -> None:
        """Test build_response with a rejected Workflow 2 run."""
        context = Mock(spec=EstCertificateRequestContext)
        run = Mock()
        run.status = Workflow2Run.STATUS_REJECTED
        context.workflow2_outcome = DispatchOutcome(status='completed', run=run, instances=[Mock()])

        EstCertificateMessageResponder.build_response(context)

        assert context.http_response_status == 403
        assert context.http_response_content_type == 'text/plain'
        assert context.http_response_content == 'Enrollment request rejected by workflow.'

    def test_build_response_rejected_workflow2_outcome_when_run_finished_after_rejection(self) -> None:
        """A rejected approval must still reject the requester even if the workflow later finished."""
        context = EstCertificateRequestContext(protocol='est', operation='simpleenroll')
        run = _create_rejected_request_run(trigger_on='est.simpleenroll')
        context.workflow2_outcome = DispatchOutcome(status='completed', run=run, instances=[])

        EstCertificateMessageResponder.build_response(context)

        assert context.http_response_status == 403
        assert context.http_response_content_type == 'text/plain'
        assert context.http_response_content == 'Enrollment request rejected by workflow.'

    def test_build_response_error_workflow2_outcome(self) -> None:
        """Test build_response with a retryable errored Workflow 2 run."""
        context = Mock(spec=EstCertificateRequestContext)
        run = Mock()
        run.id = 'run-123'
        run.status = Workflow2Run.STATUS_ERROR
        context.workflow2_outcome = DispatchOutcome(status='blocked', run=run, instances=[Mock()])

        EstCertificateMessageResponder.build_response(context)

        assert context.http_response_status == 202
        assert context.http_response_content_type == 'text/plain'
        assert context.http_response_content == 'Enrollment request pending workflow processing.'

    def test_build_response_simpleenroll_valid(
        self,
        device_instance_onboarding: dict[str, Any]
    ) -> None:
        """Test build_response with valid simpleenroll request."""
        device = device_instance_onboarding['device']
        cert = device_instance_onboarding['cert']

        context = Mock(spec=EstCertificateRequestContext)
        context.workflow2_outcome = None
        context.operation = 'simpleenroll'
        context.issued_certificate = cert
        context.est_encoding = 'pem'
        context.device = device

        EstMessageResponder.build_response(context)

        assert context.http_response_status == 200
        assert context.http_response_content_type == 'application/x-pem-file'
        assert device.onboarding_config.onboarding_status == OnboardingStatus.ONBOARDED

    def test_build_response_simplereenroll_valid(
        self,
        device_instance: dict[str, Any]
    ) -> None:
        """Test build_response with valid simplereenroll request."""
        device = device_instance['device']
        cert = device_instance['cert']

        context = Mock(spec=EstCertificateRequestContext)
        context.workflow2_outcome = None
        context.operation = 'simplereenroll'
        context.issued_certificate = cert
        context.est_encoding = 'pem'
        context.device = device

        EstMessageResponder.build_response(context)

        assert context.http_response_status == 200
        assert context.http_response_content_type == 'application/x-pem-file'

    def test_build_response_unsupported_operation(self) -> None:
        """Test build_response with unsupported operation."""
        context = Mock(spec=EstCertificateRequestContext)
        context.http_response_status = None
        context.http_response_content = None
        context.http_response_content_type = None
        context.workflow2_outcome = None
        context.operation = 'unsupported'

        EstMessageResponder.build_response(context)

        assert context.http_response_status == 500
        assert context.http_response_content == 'No suitable responder found for this EST message.'
        assert context.http_response_content_type == 'text/plain'

    def test_build_response_requires_est_context(self) -> None:
        with pytest.raises(TypeError, match='EstErrorMessageResponder requires an EstBaseRequestContext'):
            EstErrorMessageResponder.build_response(Mock(spec=BaseRequestContext))


@pytest.mark.django_db
class TestEstCertificateMessageResponder:
    """Tests for EstCertificateMessageResponder class."""

    def test_build_response_no_issued_certificate(self) -> None:
        """Test build_response when issued_certificate is None."""
        context = Mock(spec=EstCertificateRequestContext)
        context.workflow2_outcome = None
        context.issued_certificate = None

        with pytest.raises(ValueError, match='Issued certificate is not set in the context'):
            EstCertificateMessageResponder.build_response(context)

    def test_build_response_pem_encoding(
        self,
        device_instance_onboarding: dict[str, Any]
    ) -> None:
        """Test build_response with PEM encoding."""
        cert = device_instance_onboarding['cert']
        device = device_instance_onboarding['device']

        context = Mock(spec=EstCertificateRequestContext)
        context.workflow2_outcome = None
        context.issued_certificate = cert
        context.est_encoding = 'pem'
        context.device = device

        EstCertificateMessageResponder.build_response(context)

        assert context.http_response_status == 200
        assert context.http_response_content_type == 'application/x-pem-file'
        assert isinstance(context.http_response_content, str)
        assert '-----BEGIN CERTIFICATE-----' in context.http_response_content
        assert device.onboarding_config.onboarding_status == OnboardingStatus.ONBOARDED

    def test_build_response_der_encoding(
        self,
        device_instance_onboarding: dict[str, Any]
    ) -> None:
        """Test build_response with DER encoding."""
        cert = device_instance_onboarding['cert']
        device = device_instance_onboarding['device']

        context = Mock(spec=EstCertificateRequestContext)
        context.workflow2_outcome = None
        context.issued_certificate = cert
        context.est_encoding = 'der'
        context.device = device

        EstCertificateMessageResponder.build_response(context)

        assert context.http_response_status == 200
        assert context.http_response_content_type == 'application/pkix-cert'
        assert isinstance(context.http_response_content, bytes)
        assert device.onboarding_config.onboarding_status == OnboardingStatus.ONBOARDED

    def test_build_response_base64_der_encoding(
        self,
        device_instance_onboarding: dict[str, Any]
    ) -> None:
        """Test build_response with base64-encoded DER."""
        cert = device_instance_onboarding['cert']
        device = device_instance_onboarding['device']

        context = Mock(spec=EstCertificateRequestContext)
        context.workflow2_outcome = None
        context.issued_certificate = cert
        context.est_encoding = 'base64_der'
        context.device = device

        EstCertificateMessageResponder.build_response(context)

        assert context.http_response_status == 200
        assert context.http_response_content_type == 'application/pkix-cert'
        assert isinstance(context.http_response_content, str)
        assert device.onboarding_config.onboarding_status == OnboardingStatus.ONBOARDED

    def test_build_response_pkcs7_encoding(
        self,
        device_instance_onboarding: dict[str, Any]
    ) -> None:
        """Test build_response with PKCS#7 encoding."""
        cert = device_instance_onboarding['cert']
        device = device_instance_onboarding['device']

        context = Mock(spec=EstCertificateRequestContext)
        context.workflow2_outcome = None
        context.issued_certificate = cert
        context.est_encoding = 'pkcs7'
        context.device = device
        context.issued_certificate_chain = None

        EstCertificateMessageResponder.build_response(context)

        assert context.http_response_status == 200
        assert context.http_response_content_type == 'application/pkcs7-mime; smime-type=certs-only'
        assert isinstance(context.http_response_content, str)
        assert device.onboarding_config.onboarding_status == OnboardingStatus.ONBOARDED

    def test_build_response_pkcs7_includes_issued_certificate_chain(
        self,
        device_instance_onboarding: dict[str, Any],
    ) -> None:
        cert = device_instance_onboarding['cert']
        context = Mock(spec=EstCertificateRequestContext)
        context.workflow2_outcome = None
        context.issued_certificate = cert
        context.issued_certificate_chain = [cert]
        context.est_encoding = 'pkcs7'
        context.device = None

        EstCertificateMessageResponder.build_response(context)

        encoded = base64.b64decode(context.http_response_content)
        assert len(pkcs7.load_der_pkcs7_certificates(encoded)) == 2
        assert context.http_response_headers == {'Content-Transfer-Encoding': 'base64'}

    def test_prepare_certificate_data_wraps_base64_der(self, device_instance: dict[str, Any]) -> None:
        context = EstCertificateRequestContext(
            issued_certificate=device_instance['cert'],
            est_encoding='base64_der',
        )

        data, content_type = EstCertificateMessageResponder._prepare_certificate_data(context)

        assert content_type == 'application/pkix-cert'
        assert isinstance(data, str)
        assert data.endswith('\n')
        assert all(len(line) <= 64 for line in data.splitlines())
        assert base64.b64decode(data) == device_instance['cert'].public_bytes(Encoding.DER)

    def test_build_response_without_onboarding_config(
        self,
        device_instance: dict[str, Any]
    ) -> None:
        """Test build_response when device has no onboarding_config."""
        cert = device_instance['cert']
        device = device_instance['device']

        context = Mock(spec=EstCertificateRequestContext)
        context.workflow2_outcome = None
        context.issued_certificate = cert
        context.est_encoding = 'pem'
        context.device = device

        EstCertificateMessageResponder.build_response(context)

        assert context.http_response_status == 200
        assert context.http_response_content_type == 'application/x-pem-file'
        # Should not raise exception even without onboarding_config

    def test_build_response_without_device(
        self,
        device_instance: dict[str, Any]
    ) -> None:
        """Test build_response when device is None."""
        cert = device_instance['cert']

        context = Mock(spec=EstCertificateRequestContext)
        context.workflow2_outcome = None
        context.issued_certificate = cert
        context.est_encoding = 'pem'
        context.device = None

        EstCertificateMessageResponder.build_response(context)

        assert context.http_response_status == 200
        assert context.http_response_content_type == 'application/x-pem-file'

    def test_build_response_unicode_decode_error(
        self,
        device_instance: dict[str, Any]
    ) -> None:
        """Test build_response when UnicodeDecodeError occurs."""
        cert = device_instance['cert']

        context = Mock(spec=EstCertificateRequestContext)
        context.workflow2_outcome = None
        context.issued_certificate = cert
        context.est_encoding = 'invalid_encoding'
        context.device = None

        EstCertificateMessageResponder.build_response(context)

        # Should handle the error gracefully
        assert context.http_response_status in [200, 500]


@pytest.mark.django_db
class TestRestMessageResponder:
    """Tests for REST workflow-aware responders."""

    def test_build_response_pending_workflow2_outcome(self) -> None:
        """Test REST response when Workflow 2 is still waiting."""
        context = Mock(spec=RestCertificateRequestContext)
        run = Mock()
        run.status = Workflow2Run.STATUS_AWAITING
        context.workflow2_outcome = DispatchOutcome(status='blocked', run=run, instances=[Mock()])

        RestCertificateMessageResponder.build_response(context)

        assert context.http_response_status == 202
        assert context.http_response_content_type == 'application/json'
        payload = json.loads(context.http_response_content)
        assert payload['status'] == 'pending'

    def test_build_response_error_workflow2_outcome(self) -> None:
        """Test REST response when Workflow 2 is in a retryable error state."""
        context = Mock(spec=RestCertificateRequestContext)
        run = Mock()
        run.id = 'run-123'
        run.status = Workflow2Run.STATUS_ERROR
        context.workflow2_outcome = DispatchOutcome(status='blocked', run=run, instances=[Mock()])

        RestCertificateMessageResponder.build_response(context)

        assert context.http_response_status == 202
        assert context.http_response_content_type == 'application/json'
        payload = json.loads(context.http_response_content)
        assert payload['status'] == 'pending'
        assert payload['detail'] == 'Enrollment request pending workflow processing.'

    def test_build_response_valid_without_workflow2_match(
        self,
        device_instance_onboarding: dict[str, Any],
    ) -> None:
        """Test REST success response when no workflow2 definition matched."""
        device = device_instance_onboarding['device']
        cert = device_instance_onboarding['cert']

        context = Mock(spec=RestCertificateRequestContext)
        context.workflow2_outcome = None
        context.operation = 'enroll'
        context.issued_certificate = cert
        context.issued_certificate_chain = None
        context.device = device

        RestMessageResponder.build_response(context)

        assert context.http_response_status == 200
        assert context.http_response_content_type == 'application/json'
        payload = json.loads(context.http_response_content)
        assert 'certificate' in payload
        assert device.onboarding_config.onboarding_status == OnboardingStatus.ONBOARDED

    def test_build_response_rejects_unsupported_operation(self) -> None:
        context = RestBaseRequestContext(operation='unsupported')

        RestMessageResponder.build_response(context)

        assert context.http_response_status == 500
        assert json.loads(context.http_response_content) == {
            'status': 'error',
            'detail': 'No suitable responder found for this REST message.',
        }

    def test_build_response_returns_certificate_chain(self, device_instance: dict[str, Any]) -> None:
        cert = device_instance['cert']
        context = RestCertificateRequestContext(
            operation='enroll',
            issued_certificate=cert,
            issued_certificate_chain=[cert],
        )

        RestCertificateMessageResponder.build_response(context)

        payload = json.loads(context.http_response_content)
        assert payload['certificate'].startswith('-----BEGIN CERTIFICATE-----')
        assert payload['certificate_chain'] == [payload['certificate']]

    @pytest.mark.parametrize(
        ('decision', 'status', 'response_status'),
        [
            ('reject', 'rejected', 403),
            ('fail', 'failed', 500),
            ('unknown', 'error', 500),
        ],
    )
    def test_workflow_terminal_outcomes_are_json_errors(
        self, decision: str, status: str, response_status: int
    ) -> None:
        context = Mock(spec=RestCertificateRequestContext)
        context.workflow2_outcome = Mock(run=Mock(status='finished'))

        with (
            patch(
                'request.message_responder.rest.get_workflow2_issuance_decision',
                return_value=(
                    decision
                    if decision == 'unknown'
                    else Workflow2IssuanceDecision(decision)
                ),
            ),
            patch('request.message_responder.rest.get_workflow2_run_detail_path', return_value='/runs/1'),
        ):
            RestCertificateMessageResponder.build_response(context)

        payload = json.loads(context.http_response_content)
        assert context.http_response_status == response_status
        assert payload['status'] == status

    def test_build_response_requires_rest_context(self) -> None:
        with pytest.raises(TypeError, match='RestMessageResponder requires a RestBaseRequestContext'):
            RestMessageResponder.build_response(Mock(spec=BaseRequestContext))


@pytest.mark.django_db
class TestEstErrorMessageResponder:
    """Tests for EstErrorMessageResponder class."""

    def test_build_response_default_values(self) -> None:
        """Test build_response with default status and message."""
        context = Mock(spec=EstBaseRequestContext)
        context.http_response_status = None
        context.http_response_content = None
        context.http_response_content_type = None

        EstErrorMessageResponder.build_response(context)

        assert context.http_response_status == 500
        assert context.http_response_content_type == 'text/plain'
        assert context.http_response_content == 'An error occurred processing the EST request.'

    def test_build_response_custom_values(self) -> None:
        """Test build_response with custom status and message."""
        context = Mock(spec=EstBaseRequestContext)
        context.http_response_status = 404
        context.http_response_content = 'Not found'
        context.http_response_content_type = 'text/html'

        EstErrorMessageResponder.build_response(context)

        assert context.http_response_status == 404
        assert context.http_response_content_type == 'text/html'
        assert context.http_response_content == 'Not found'

    def test_build_response_partial_defaults(self) -> None:
        """Test build_response with only custom status."""
        context = Mock(spec=EstBaseRequestContext)
        context.http_response_status = 400
        context.http_response_content = None
        context.http_response_content_type = None

        EstErrorMessageResponder.build_response(context)

        assert context.http_response_status == 400
        assert context.http_response_content_type == 'text/plain'
        assert context.http_response_content == 'An error occurred processing the EST request.'

    def test_build_response_requires_est_context(self) -> None:
        with pytest.raises(TypeError, match='EstErrorMessageResponder requires an EstBaseRequestContext'):
            EstErrorMessageResponder.build_response(Mock(spec=BaseRequestContext))


@pytest.mark.django_db
class TestRestErrorMessageResponder:
    """Tests for RestErrorMessageResponder class."""

    def test_build_response_default_values(self) -> None:
        """Test build_response with default REST error values."""
        context = Mock(spec=RestBaseRequestContext)
        context.http_response_status = None
        context.http_response_content = None
        context.http_response_content_type = None

        RestErrorMessageResponder.build_response(context)

        assert context.http_response_status == 500
        assert context.http_response_content_type == 'application/json'
        assert json.loads(context.http_response_content) == {
            'status': 'error',
            'detail': 'An error occurred processing the REST request.',
        }

    def test_build_response_decodes_byte_detail(self) -> None:
        context = RestBaseRequestContext(http_response_status=400, http_response_content=b'bad request')

        RestErrorMessageResponder.build_response(context)

        assert json.loads(context.http_response_content) == {
            'status': 'error',
            'detail': 'bad request',
        }

    def test_build_response_requires_rest_context(self) -> None:
        with pytest.raises(TypeError, match='RestErrorMessageResponder requires a RestBaseRequestContext'):
            RestErrorMessageResponder.build_response(Mock(spec=BaseRequestContext))


class TestCmpTransactionResponder:
    """Tests for CMP transaction-aware enrollment and polling responses."""

    def test_build_response_waiting_transaction_for_initial_request(self) -> None:
        context = Mock(spec=CmpCertificateRequestContext)
        context.operation = 'initialization'
        context.issued_certificate = None
        context.cmp_transaction = Mock(
            status=CmpTransactionModel.Status.WAITING,
            detail='Enrollment request pending workflow approval.',
        )

        with (
            patch.object(CmpTransactionResponder, '_resolve_issuer_credential', return_value=Mock()),
            patch.object(CmpTransactionResponder, '_build_sender_kid', return_value=Mock()),
            patch.object(CmpInitializationResponder, '_build_base_ip_message', return_value=Mock()) as build_message,
            patch.object(CmpTransactionResponder, '_protect_pki_message', side_effect=lambda pki_message, **_: pki_message),
            patch('request.message_responder.cmp.encoder.encode', return_value=b'cmp-pending'),
        ):
            handled = CmpTransactionResponder.respond_if_needed(context)

        assert handled is True
        assert build_message.call_args.kwargs['status'] == 3
        assert build_message.call_args.kwargs['status_text'] == 'Enrollment request pending workflow approval.'
        assert context.http_response_status == 200
        assert context.http_response_content == b'cmp-pending'
        assert context.http_response_content_type == 'application/pkixcmp'

    def test_build_response_rejected_transaction_for_initial_request(self) -> None:
        context = Mock(spec=CmpCertificateRequestContext)
        context.operation = 'initialization'
        context.issued_certificate = None
        context.cmp_transaction = Mock(
            status=CmpTransactionModel.Status.REJECTED,
            detail='Enrollment request rejected by workflow.',
        )

        with (
            patch.object(CmpTransactionResponder, '_resolve_issuer_credential', return_value=Mock()),
            patch.object(CmpTransactionResponder, '_build_sender_kid', return_value=Mock()),
            patch.object(CmpInitializationResponder, '_build_base_ip_message', return_value=Mock()) as build_message,
            patch.object(CmpTransactionResponder, '_protect_pki_message', side_effect=lambda pki_message, **_: pki_message),
            patch('request.message_responder.cmp.encoder.encode', return_value=b'cmp-rejected'),
        ):
            handled = CmpTransactionResponder.respond_if_needed(context)

        assert handled is True
        assert build_message.call_args.kwargs['status'] == 2
        assert build_message.call_args.kwargs['status_text'] == 'Enrollment request rejected by workflow.'
        assert context.http_response_content == b'cmp-rejected'

    def test_build_response_waiting_poll_request_returns_pollrep(self) -> None:
        context = Mock(spec=CmpPollRequestContext)
        context.operation = 'initialization'
        context.issued_certificate = None
        context.poll_cert_req_id = 0
        context.cmp_transaction = Mock(
            status=CmpTransactionModel.Status.WAITING,
            detail='Enrollment request pending workflow approval.',
            check_after_seconds=5,
        )

        with (
            patch.object(CmpTransactionResponder, '_build_pollrep_message', return_value=Mock()) as build_pollrep,
            patch.object(CmpTransactionResponder, '_protect_pki_message', side_effect=lambda pki_message, **_: pki_message),
            patch('request.message_responder.cmp.encoder.encode', return_value=b'cmp-pollrep'),
        ):
            handled = CmpTransactionResponder.respond_if_needed(context)

        assert handled is True
        assert build_pollrep.call_args.kwargs['check_after_seconds'] == 5
        assert context.http_response_status == 200
        assert context.http_response_content == b'cmp-pollrep'

    def test_terminal_poll_states_build_transaction_result(self) -> None:
        for transaction_status in (
            CmpTransactionModel.Status.CANCELLED,
            CmpTransactionModel.Status.FAILED,
        ):
            context = Mock(spec=CmpPollRequestContext)
            context.issued_certificate = None
            context.cmp_transaction = Mock(status=transaction_status, detail=None)
            with (
                patch.object(CmpTransactionResponder, '_build_transaction_result_message', return_value=Mock()) as build,
                patch.object(CmpTransactionResponder, '_protect_pki_message', side_effect=lambda message, **_: message),
                patch('request.message_responder.cmp.encoder.encode', return_value=b'terminal'),
            ):
                assert CmpTransactionResponder.respond_if_needed(context) is True
            assert build.call_args.kwargs['status'] == 2
            assert context.http_response_content == b'terminal'

    def test_poll_with_issued_certificate_returns_result(self) -> None:
        context = Mock(spec=CmpPollRequestContext)
        context.issued_certificate = Mock()
        context.cmp_transaction = Mock(status=CmpTransactionModel.Status.WAITING)
        with (
            patch.object(CmpTransactionResponder, '_build_transaction_result_message', return_value=Mock()) as build,
            patch.object(CmpTransactionResponder, '_protect_pki_message', side_effect=lambda message, **_: message),
            patch('request.message_responder.cmp.encoder.encode', return_value=b'issued'),
        ):
            assert CmpTransactionResponder.respond_if_needed(context) is True
        assert build.call_args.kwargs['status'] == 0
        assert build.call_args.kwargs['issued_cert'] is context.issued_certificate

    def test_unknown_operation_does_not_handle_transaction(self) -> None:
        context = Mock(spec=CmpCertificateRequestContext)
        context.issued_certificate = None
        context.operation = 'unknown'
        context.cmp_transaction = Mock(status=CmpTransactionModel.Status.FAILED, detail='failed')
        with patch.object(CmpTransactionResponder, '_build_transaction_result_message', return_value=None):
            assert CmpTransactionResponder.respond_if_needed(context) is False


class TestCmpResponderValidation:
    """Test CMP responder routing and protection preconditions."""

    def test_der_tlv_uses_long_form_for_large_values(self) -> None:
        encoded = _der_tlv(0x04, b'x' * 128)
        assert encoded[:3] == b'\x04\x81\x80'
        assert encoded[3:] == b'x' * 128

    def test_build_response_returns_cmp_error_for_authorization_failure(self) -> None:
        context = Mock(spec=BaseRequestContext)
        context.error_details = 'unauthorized'
        context.http_response_status = 403
        context.http_response_content = None
        context.http_response_content_type = None

        with patch.object(CmpErrorMessageResponder, 'build_response') as build_error:
            CmpMessageResponder.build_response(context)

        build_error.assert_called_once_with(context)

    def test_build_response_sets_error_when_no_responder_matches(self) -> None:
        context = Mock(spec=BaseRequestContext)
        context.error_details = None
        context.http_response_status = None
        context.issued_certificate = None
        context.workflow2_outcome = None

        with patch.object(CmpErrorMessageResponder, 'build_response') as build_error:
            CmpMessageResponder.build_response(context)

        assert context.http_response_status == 500
        assert context.http_response_content == 'No suitable responder found for this CMP message.'
        build_error.assert_called_once_with(context)

    def test_shared_secret_protection_requires_secret(self) -> None:
        context = Mock(spec=CmpBaseRequestContext)
        context.cmp_shared_secret = None
        with pytest.raises(ValueError, match='CMP shared secret is not set'):
            CmpMessageResponder._add_protection_shared_secret(Mock(), context)

    def test_initialization_responder_requires_issuer_credential(self) -> None:
        context = Mock(spec=CmpCertificateRequestContext)
        context.issued_certificate = Mock()
        context.issuer_credential = None
        with pytest.raises(ValueError, match='Issuer credential is not set'):
            CmpInitializationResponder.build_response(context)

    def test_protection_helpers_choose_shared_secret_or_signature(self) -> None:
        context = Mock(spec=CmpCertificateRequestContext)
        message = Mock()
        context.cmp_shared_secret = 'shared-secret'
        with patch.object(CmpMessageResponder, '_add_protection_shared_secret', return_value=message) as shared:
            assert CmpTransactionResponder._protect_pki_message(message, context=context) is message
        shared.assert_called_once()

        context.cmp_shared_secret = None
        with patch.object(CmpMessageResponder, '_sign_pki_message', return_value=message) as signed:
            assert CmpTransactionResponder._protect_pki_message(message, context=context) is message
        signed.assert_called_once()

    def test_error_response_type_for_operations(self) -> None:
        assert CmpErrorMessageResponder._get_response_type_for_operation('initialization') == ('ip', 1)
        assert CmpErrorMessageResponder._get_response_type_for_operation('certification') == ('cp', 3)
        assert CmpErrorMessageResponder._get_response_type_for_operation('revocation') == ('rp', 12)
        assert CmpErrorMessageResponder._get_response_type_for_operation(None) == ('error', 23)

    def test_pki_conf_rejects_missing_issuer_credential(self) -> None:
        context = Mock(spec=CmpCertConfRequestContext)
        context.issuer_credential = None
        context.domain = None
        with pytest.raises(ValueError, match='Cannot determine issuing CA credential'):
            CmpPkiConfResponder.build_response(context)

    def test_pki_conf_builds_signed_response(self) -> None:
        context = Mock(spec=CmpCertConfRequestContext)
        context.issuer_credential = Mock()
        context.owner_credential = None
        context.cmp_shared_secret = None
        context.cert_conf_status = 0
        context.device = None
        context.parsed_message = Mock()
        with (
            patch.object(CmpPkiConfResponder, '_build_base_pkiconf_message', return_value=Mock()),
            patch.object(CmpPkiConfResponder, '_sign_pki_message', side_effect=lambda pki_message, **_: pki_message) as sign,
            patch('request.message_responder.cmp.x509.SubjectKeyIdentifier.from_public_key', return_value=Mock(digest=b'ski')),
            patch('request.message_responder.cmp.encoder.encode', return_value=b'pkiconf'),
        ):
            CmpPkiConfResponder.build_response(context)
        sign.assert_called_once()
        assert context.http_response_content == b'pkiconf'
