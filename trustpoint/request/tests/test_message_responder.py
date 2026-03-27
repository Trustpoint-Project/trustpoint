"""Tests for request/message_responder.py."""

import json
from typing import Any
from unittest.mock import Mock, patch

import pytest

from onboarding.models import OnboardingStatus
from request.message_responder.cmp import CmpCertificateWorkflowResponder, CmpInitializationResponder
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
    CmpCertificateRequestContext,
    EstBaseRequestContext,
    EstCertificateRequestContext,
    RestBaseRequestContext,
    RestCertificateRequestContext,
)
from workflows2.models import Workflow2Run
from workflows2.services.dispatch import DispatchOutcome


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

    def test_build_response_failed_workflow2_outcome(self) -> None:
        """Test build_response with a failed Workflow 2 run."""
        context = Mock(spec=EstCertificateRequestContext)
        run = Mock()
        run.id = 'run-123'
        run.status = Workflow2Run.STATUS_FAILED
        context.workflow2_outcome = DispatchOutcome(status='completed', run=run, instances=[Mock()])

        EstCertificateMessageResponder.build_response(context)

        assert context.http_response_status == 500
        assert context.http_response_content_type == 'text/plain'
        assert '/workflows2/runs/run-123/' in context.http_response_content

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

    def test_build_response_failed_workflow2_outcome(self) -> None:
        """Test REST response when Workflow 2 failed."""
        context = Mock(spec=RestCertificateRequestContext)
        run = Mock()
        run.id = 'run-123'
        run.status = Workflow2Run.STATUS_FAILED
        context.workflow2_outcome = DispatchOutcome(status='completed', run=run, instances=[Mock()])

        RestCertificateMessageResponder.build_response(context)

        assert context.http_response_status == 500
        assert context.http_response_content_type == 'application/json'
        payload = json.loads(context.http_response_content)
        assert payload['status'] == 'failed'
        assert '/workflows2/runs/run-123/' in payload['detail']

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


@pytest.mark.django_db
class TestCmpCertificateWorkflowResponder:
    """Tests for CMP workflow-aware enrollment responses."""

    def test_build_response_pending_workflow2_outcome(self) -> None:
        context = Mock(spec=CmpCertificateRequestContext)
        context.operation = 'initialization'
        context.workflow2_outcome = DispatchOutcome(
            status='blocked',
            run=Mock(status=Workflow2Run.STATUS_AWAITING),
            instances=[Mock()],
        )

        with (
            patch.object(CmpCertificateWorkflowResponder, '_resolve_issuer_credential', return_value=Mock()),
            patch.object(CmpCertificateWorkflowResponder, '_build_sender_kid', return_value=Mock()),
            patch.object(CmpInitializationResponder, '_build_base_ip_message', return_value=Mock()) as build_message,
            patch.object(CmpCertificateWorkflowResponder, '_protect_pki_message', side_effect=lambda pki_message, **_: pki_message),
            patch('request.message_responder.cmp.encoder.encode', return_value=b'cmp-pending'),
        ):
            handled = CmpCertificateWorkflowResponder.respond_if_needed(context)

        assert handled is True
        assert build_message.call_args.kwargs['status'] == 3
        assert build_message.call_args.kwargs['status_text'] == 'Enrollment request pending workflow approval.'
        assert context.http_response_status == 200
        assert context.http_response_content == b'cmp-pending'
        assert context.http_response_content_type == 'application/pkixcmp'

    def test_build_response_rejected_workflow2_outcome(self) -> None:
        context = Mock(spec=CmpCertificateRequestContext)
        context.operation = 'initialization'
        context.workflow2_outcome = DispatchOutcome(
            status='completed',
            run=Mock(status=Workflow2Run.STATUS_REJECTED),
            instances=[Mock()],
        )

        with (
            patch.object(CmpCertificateWorkflowResponder, '_resolve_issuer_credential', return_value=Mock()),
            patch.object(CmpCertificateWorkflowResponder, '_build_sender_kid', return_value=Mock()),
            patch.object(CmpInitializationResponder, '_build_base_ip_message', return_value=Mock()) as build_message,
            patch.object(CmpCertificateWorkflowResponder, '_protect_pki_message', side_effect=lambda pki_message, **_: pki_message),
            patch('request.message_responder.cmp.encoder.encode', return_value=b'cmp-rejected'),
        ):
            handled = CmpCertificateWorkflowResponder.respond_if_needed(context)

        assert handled is True
        assert build_message.call_args.kwargs['status'] == 2
        assert build_message.call_args.kwargs['status_text'] == 'Enrollment request rejected by workflow.'
        assert context.http_response_content == b'cmp-rejected'
