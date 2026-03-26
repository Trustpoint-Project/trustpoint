"""REST-specific message responder classes."""

import json

from cryptography.hazmat.primitives.serialization import Encoding

from onboarding.models import OnboardingStatus
from request.request_context import BaseRequestContext, RestBaseRequestContext, RestCertificateRequestContext
from request.workflows2_gate import get_workflow2_outcome, workflow2_run_detail_path
from workflows2.models import Workflow2Run

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
        workflow2_outcome = get_workflow2_outcome(context)
        if workflow2_outcome is None or workflow2_outcome.status == 'no_match':
            return True

        run_status = str(workflow2_outcome.run.status)
        if run_status in {
            Workflow2Run.STATUS_QUEUED,
            Workflow2Run.STATUS_RUNNING,
            Workflow2Run.STATUS_AWAITING,
            Workflow2Run.STATUS_PAUSED,
        }:
            context.http_response_status = 202
            context.http_response_content_type = 'application/json'
            context.http_response_content = json.dumps(
                {'status': 'pending', 'detail': 'Enrollment request pending workflow approval.'}
            )
            return False
        if run_status == Workflow2Run.STATUS_REJECTED:
            context.http_response_status = 403
            context.http_response_content_type = 'application/json'
            context.http_response_content = json.dumps(
                {'status': 'rejected', 'detail': 'Enrollment request rejected by workflow.'}
            )
            return False
        if run_status in {
            Workflow2Run.STATUS_FAILED,
            Workflow2Run.STATUS_CANCELLED,
            Workflow2Run.STATUS_STOPPED,
        }:
            detail = 'Enrollment request failed in workflow processing.'
            run_path = workflow2_run_detail_path(context)
            if run_path:
                detail = f'{detail} Check here: -> {run_path}'
            context.http_response_status = 500
            context.http_response_content_type = 'application/json'
            context.http_response_content = json.dumps({'status': 'failed', 'detail': detail})
            return False
        if run_status in {Workflow2Run.STATUS_NO_MATCH, Workflow2Run.STATUS_SUCCEEDED}:
            return True

        context.http_response_status = 500
        context.http_response_content_type = 'application/json'
        context.http_response_content = json.dumps({
            'status': 'error',
            'detail': f'Enrollment request is in an unsupported workflow state: {run_status}.',
        })
        return False

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
