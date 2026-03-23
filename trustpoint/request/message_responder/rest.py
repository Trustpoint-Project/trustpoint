"""REST-specific message responder classes."""

import json

from cryptography.hazmat.primitives.serialization import Encoding

from onboarding.models import OnboardingStatus
from request.request_context import BaseRequestContext, RestBaseRequestContext, RestCertificateRequestContext
from workflows.models import State

from .base import AbstractMessageResponder


class RestMessageResponder(AbstractMessageResponder):
    """Builds response to REST API requests."""

    @staticmethod
    def build_response(context: BaseRequestContext) -> None:
        """Respond to a REST message."""
        if not isinstance(context, RestBaseRequestContext):
            exc_msg = 'RestMessageResponder requires a RestBaseRequestContext.'
            raise TypeError(exc_msg)

        if context.operation in ['enroll', 'reenroll']:
            responder = RestCertificateMessageResponder()
            return responder.build_response(context)
        exc_msg = 'No suitable responder found for this REST message.'
        context.http_response_status = 500
        context.http_response_content = exc_msg
        return RestErrorMessageResponder().build_response(context)


class RestCertificateMessageResponder(RestMessageResponder):
    """Respond to a REST enrollment request with the issued certificate."""

    @staticmethod
    def _check_workflow_state(context: RestCertificateRequestContext) -> bool:
        """Check if the workflow state allows for certificate issuance."""
        if not context.enrollment_request:
            exc_msg = 'No enrollment request is set in the context.'
            raise ValueError(exc_msg)

        workflow_state = context.enrollment_request.aggregated_state
        if workflow_state == State.AWAITING:
            context.http_response_status = 202
            context.http_response_content_type = 'application/json'
            context.http_response_content = json.dumps(
                {'status': 'pending', 'detail': 'Enrollment request pending manual approval.'}
            )
            return False
        if workflow_state == State.REJECTED:
            context.enrollment_request.finalize(State.REJECTED)
            context.http_response_status = 403
            context.http_response_content_type = 'application/json'
            context.http_response_content = json.dumps({'status': 'rejected', 'detail': 'Enrollment request rejected.'})
            return False
        if workflow_state == State.FAILED:
            context.http_response_status = 500
            context.http_response_content_type = 'application/json'
            context.http_response_content = json.dumps({
                'status': 'failed',
                'detail': f'Workflow failed. Check here: -> /workflows/requests/{context.enrollment_request.id}',
            })
            return False
        if not context.enrollment_request.is_valid():
            context.http_response_status = 500
            context.http_response_content_type = 'application/json'
            context.http_response_content = json.dumps({
                'status': 'error',
                'detail': 'Enrollment request is not in a valid state for certificate issuance.',
            })
            return False
        context.enrollment_request.finalize(State.FINALIZED)
        return True

    @staticmethod
    def build_response(context: BaseRequestContext) -> None:
        """Respond to a REST enrollment request with the issued certificate as PEM in JSON."""
        if not isinstance(context, RestCertificateRequestContext):
            exc_msg = 'RestCertificateMessageResponder requires a RestCertificateRequestContext.'
            raise TypeError(exc_msg)

        if not RestCertificateMessageResponder._check_workflow_state(context):
            return

        if context.issued_certificate is None:
            exc_msg = 'Issued certificate is not set in the context.'
            raise ValueError(exc_msg)

        cert_pem = context.issued_certificate.public_bytes(Encoding.PEM).decode('utf-8')

        chain_pem_list = []
        if context.issued_certificate_chain:
            chain_pem_list = [
                cert.public_bytes(Encoding.PEM).decode('utf-8')
                for cert in context.issued_certificate_chain
            ]

        response_data = {
            'certificate': cert_pem,
            'certificate_chain': chain_pem_list,
        }

        if context.device and context.device.onboarding_config:
            context.device.onboarding_config.onboarding_status = OnboardingStatus.ONBOARDED
            context.device.onboarding_config.save()

        context.http_response_status = 200
        context.http_response_content = json.dumps(response_data)
        context.http_response_content_type = 'application/json'


class RestErrorMessageResponder(RestMessageResponder):
    """Respond to a REST request with an error JSON payload."""

    @staticmethod
    def build_response(context: BaseRequestContext) -> None:
        """Respond to a REST request with an error."""
        if not isinstance(context, RestBaseRequestContext):
            exc_msg = 'RestErrorMessageResponder requires a RestBaseRequestContext.'
            raise TypeError(exc_msg)

        status = context.http_response_status or 500
        detail = context.http_response_content or 'An error occurred processing the REST request.'
        if isinstance(detail, bytes):
            detail = detail.decode('utf-8')

        context.http_response_status = status
        context.http_response_content = json.dumps({'status': 'error', 'detail': detail})
        context.http_response_content_type = 'application/json'
