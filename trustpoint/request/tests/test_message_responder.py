"""Tests for request/message_responder.py."""

from typing import Any
from unittest.mock import Mock

import pytest

from onboarding.models import OnboardingStatus
from request.message_responder.est import (
    EstCertificateMessageResponder,
    EstErrorMessageResponder,
    EstMessageResponder,
)
from request.request_context import BaseRequestContext, EstBaseRequestContext, EstCertificateRequestContext
from workflows.models import State


@pytest.mark.django_db
class TestEstMessageResponder:
    """Tests for EstMessageResponder class."""

    def test_incorrect_context_type(self) -> None:
        context = Mock(spec=BaseRequestContext)

        with pytest.raises(TypeError, match='EstMessageResponder requires a subclass of EstBaseRequestContext.'):
            EstMessageResponder.build_response(context)

    def test_build_response_no_enrollment_request(self) -> None:
        """Test build_response when enrollment_request is None."""
        context = Mock(spec=EstCertificateRequestContext)
        context.enrollment_request = None

        with pytest.raises(ValueError, match='No enrollment request is set in the context'):
            EstCertificateMessageResponder.build_response(context)

    def test_build_response_awaiting_state(self) -> None:
        """Test build_response with AWAITING state."""
        context = Mock(spec=EstCertificateRequestContext)
        enrollment_request = Mock()
        enrollment_request.aggregated_state = State.AWAITING
        context.enrollment_request = enrollment_request

        EstCertificateMessageResponder.build_response(context)

        assert context.http_response_status == 202
        assert context.http_response_content_type == 'text/plain'
        assert context.http_response_content == 'Enrollment request pending manual approval.'

    def test_build_response_rejected_state(self) -> None:
        """Test build_response with REJECTED state."""
        context = Mock(spec=EstCertificateRequestContext)
        enrollment_request = Mock()
        enrollment_request.aggregated_state = State.REJECTED
        context.enrollment_request = enrollment_request

        EstCertificateMessageResponder.build_response(context)

        enrollment_request.finalize.assert_called_once_with(State.REJECTED)
        assert context.http_response_status == 403
        assert context.http_response_content_type == 'text/plain'
        assert context.http_response_content == 'Enrollment request Rejected.'

    def test_build_response_failed_state(self) -> None:
        """Test build_response with FAILED state."""
        context = Mock(spec=EstCertificateRequestContext)
        enrollment_request = Mock()
        enrollment_request.aggregated_state = State.FAILED
        enrollment_request.id = 123
        context.enrollment_request = enrollment_request

        EstCertificateMessageResponder.build_response(context)

        assert context.http_response_status == 500
        assert context.http_response_content_type == 'text/plain'
        assert 'Workflow failed' in context.http_response_content
        assert '/workflows/requests/123' in context.http_response_content

    def test_build_response_simpleenroll_valid(
        self,
        device_instance_onboarding: dict[str, Any]
    ) -> None:
        """Test build_response with valid simpleenroll request."""
        device = device_instance_onboarding['device']
        cert = device_instance_onboarding['cert']

        context = Mock(spec=EstCertificateRequestContext)
        enrollment_request = Mock()
        enrollment_request.aggregated_state = State.APPROVED
        enrollment_request.is_valid.return_value = True
        context.enrollment_request = enrollment_request
        context.operation = 'simpleenroll'
        context.issued_certificate = cert
        context.est_encoding = 'pem'
        context.device = device

        EstMessageResponder.build_response(context)

        enrollment_request.finalize.assert_called_once_with(State.FINALIZED)
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
        enrollment_request = Mock()
        enrollment_request.aggregated_state = State.APPROVED
        enrollment_request.is_valid.return_value = True
        context.enrollment_request = enrollment_request
        context.operation = 'simplereenroll'
        context.issued_certificate = cert
        context.est_encoding = 'pem'
        context.device = device

        EstMessageResponder.build_response(context)

        enrollment_request.finalize.assert_called_once_with(State.FINALIZED)
        assert context.http_response_status == 200
        assert context.http_response_content_type == 'application/x-pem-file'

    def test_build_response_invalid_request(self) -> None:
        """Test build_response with invalid enrollment request."""
        context = Mock(spec=EstCertificateRequestContext)
        context.http_response_status = None
        context.http_response_content = None
        context.http_response_content_type = None
        enrollment_request = Mock()
        enrollment_request.aggregated_state = State.APPROVED
        enrollment_request.is_valid.return_value = False
        context.enrollment_request = enrollment_request

        EstMessageResponder.build_response(context)

        assert context.http_response_status == 500
        assert context.http_response_content_type == 'text/plain'
        assert context.http_response_content == 'No suitable responder found for this EST message.'

    def test_build_response_unsupported_operation(self) -> None:
        """Test build_response with unsupported operation."""
        context = Mock(spec=EstCertificateRequestContext)
        context.http_response_status = None
        context.http_response_content = None
        context.http_response_content_type = None
        enrollment_request = Mock()
        enrollment_request.aggregated_state = State.APPROVED
        enrollment_request.is_valid.return_value = True
        context.enrollment_request = enrollment_request
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
        context.issued_certificate = cert
        context.est_encoding = 'pkcs7'
        context.device = device

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
        context.issued_certificate = cert
        context.est_encoding = 'invalid_encoding'
        context.device = None

        EstCertificateMessageResponder.build_response(context)

        # Should handle the error gracefully
        assert context.http_response_status in [200, 500]


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
