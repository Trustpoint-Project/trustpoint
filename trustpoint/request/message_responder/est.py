"""EST-specific message responder classes."""
import base64

from cryptography.hazmat.primitives.serialization import Encoding, pkcs7

from onboarding.models import OnboardingStatus
from request.request_context import BaseRequestContext, EstBaseRequestContext, EstCertificateRequestContext
from request.workflows2_gate import get_workflow2_outcome, workflow2_run_detail_path
from workflows2.models import Workflow2Run

from .base import AbstractMessageResponder


class EstMessageResponder(AbstractMessageResponder):
    """Builds response to EST requests."""

    @staticmethod
    def build_response(context: BaseRequestContext) -> None:
        """Respond to an EST message."""
        if not isinstance(context, EstBaseRequestContext):
            exc_msg = 'EstMessageResponder requires a subclass of EstBaseRequestContext.'
            raise TypeError(exc_msg)

        if context.operation in ['simpleenroll', 'simplereenroll']:
            responder = EstCertificateMessageResponder()
            return responder.build_response(context)
        exc_msg = 'No suitable responder found for this EST message.'
        context.http_response_status = 500
        context.http_response_content = exc_msg
        return EstErrorMessageResponder().build_response(context)


class EstCertificateMessageResponder(EstMessageResponder):
    """Respond to an EST enrollment message with the issued certificate."""

    @staticmethod
    def _check_workflow_state(context: EstCertificateRequestContext) -> bool:
        """Check if the workflow state allows for certificate issuance."""
        workflow2_outcome = get_workflow2_outcome(context)
        if workflow2_outcome is None:
            return True

        run_status = str(workflow2_outcome.run.status)
        if run_status in {
            Workflow2Run.STATUS_QUEUED,
            Workflow2Run.STATUS_RUNNING,
            Workflow2Run.STATUS_AWAITING,
            Workflow2Run.STATUS_PAUSED,
        }:
            status = 202
            detail = 'Enrollment request pending workflow approval.'
        elif run_status == Workflow2Run.STATUS_REJECTED:
            status = 403
            detail = 'Enrollment request rejected by workflow.'
        elif run_status in {
            Workflow2Run.STATUS_FAILED,
            Workflow2Run.STATUS_CANCELLED,
            Workflow2Run.STATUS_STOPPED,
        }:
            detail = 'Enrollment request failed in workflow processing.'
            run_path = workflow2_run_detail_path(context)
            if run_path:
                detail = f'{detail} Check here: -> {run_path}'
            status = 500
        elif run_status == Workflow2Run.STATUS_SUCCEEDED:
            return True
        else:
            status = 500
            detail = f'Enrollment request is in an unsupported workflow state: {run_status}.'

        context.http_response_status = status
        context.http_response_content_type = 'text/plain'
        context.http_response_content = detail
        return False

    @staticmethod
    def _prepare_certificate_data(context: EstCertificateRequestContext) -> tuple[str | bytes, str]:
        """Prepare the certificate data and content type based on encoding."""
        if context.issued_certificate is None:
            exc_msg = 'Issued certificate is not set in the context.'
            raise ValueError(exc_msg)

        encoding: Encoding = Encoding.PEM
        if context.est_encoding in {'der', 'base64_der', 'pkcs7'}:
            encoding = Encoding.DER

        if context.est_encoding == 'pkcs7':
            chain = [context.issued_certificate]
            if context.issued_certificate_chain:
                chain.extend(context.issued_certificate_chain)
            cert_bytes = pkcs7.serialize_certificates(chain, encoding=Encoding.DER)
        else:
            cert_bytes = context.issued_certificate.public_bytes(encoding=encoding)

        if context.est_encoding == 'der':
            return cert_bytes, 'application/pkix-cert'
        if context.est_encoding == 'pem':
            cert: str | bytes
            try:
                cert = cert_bytes.decode('utf-8')
            except UnicodeDecodeError:
                cert = cert_bytes
            return cert, 'application/x-pem-file'
        # Default to RFC 7030 compliant format: base64-encoded with line wrapping
        b64_cert = base64.b64encode(cert_bytes).decode('utf-8')
        cert = '\n'.join([b64_cert[i:i + 64] for i in range(0, len(b64_cert), 64)]) + '\n'
        if context.est_encoding == 'base64_der':
            content_type = 'application/pkix-cert'
        else:
            content_type = 'application/pkcs7-mime; smime-type=certs-only'
        return cert, content_type

    @staticmethod
    def build_response(context: BaseRequestContext) -> None:
        """Respond to an EST enrollment message with the issued certificate."""
        if not isinstance(context, EstCertificateRequestContext):
            exc_msg = 'EstCertificateMessageResponder requires an EstCertificateRequestContext.'
            raise TypeError(exc_msg)

        if not EstCertificateMessageResponder._check_workflow_state(context):
            return
        if context.issued_certificate is None:
            exc_msg = 'Issued certificate is not set in the context.'
            raise ValueError(exc_msg)

        cert, content_type = EstCertificateMessageResponder._prepare_certificate_data(context)

        if context.device and context.device.onboarding_config:
            context.device.onboarding_config.onboarding_status = OnboardingStatus.ONBOARDED
            context.device.onboarding_config.save()
        context.http_response_status = 200
        context.http_response_content = cert
        context.http_response_content_type = content_type
        if context.est_encoding in {'pkcs7', 'base64_der'}:
            context.http_response_headers = {'Content-Transfer-Encoding': 'base64'}


class EstErrorMessageResponder(EstMessageResponder):
    """Respond to an EST message with an error."""

    @staticmethod
    def build_response(context: BaseRequestContext) -> None:
        """Respond to an EST message with an error."""
        # Set appropriate HTTP status code and error message in context
        if not isinstance(context, EstBaseRequestContext):
            exc_msg = 'EstErrorMessageResponder requires an EstBaseRequestContext.'
            raise TypeError(exc_msg)
        context.http_response_status = context.http_response_status or 500
        context.http_response_content = context.http_response_content or 'An error occurred processing the EST request.'
        context.http_response_content_type = context.http_response_content_type or 'text/plain'
