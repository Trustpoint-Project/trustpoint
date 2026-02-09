"""EST-specific message responder classes."""
import base64

from cryptography.hazmat.primitives.serialization import Encoding, pkcs7

from onboarding.models import OnboardingStatus
from request.request_context import BaseRequestContext, EstBaseRequestContext, EstCertificateRequestContext
from workflows.models import State

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
        if not context.enrollment_request:
            exc_msg = 'No enrollment request is set in the context.'
            raise ValueError(exc_msg)

        workflow_state = context.enrollment_request.aggregated_state
        if workflow_state == State.AWAITING:
            context.http_response_status = 202
            context.http_response_content_type = 'text/plain'
            context.http_response_content = 'Enrollment request pending manual approval.'
            # TODO(Air): Implement Retry-After header  # noqa: FIX002
            return False
        if workflow_state == State.REJECTED:
            context.enrollment_request.finalize(State.REJECTED)
            context.http_response_status = 403
            context.http_response_content_type = 'text/plain'
            context.http_response_content = 'Enrollment request Rejected.'
            return False
        if workflow_state == State.FAILED:
            context.http_response_status = 500
            context.http_response_content_type = 'text/plain'
            context.http_response_content = \
                f'Workflow failed. Check here: -> /workflows/requests/{context.enrollment_request.id}'
            return False
        if not context.enrollment_request.is_valid():
            context.http_response_status = 500
            context.http_response_content_type = 'text/plain'
            context.http_response_content = 'Enrollment request is not in a valid state for certificate issuance.'
            return False
        context.enrollment_request.finalize(State.FINALIZED)
        return True

    @staticmethod
    def build_response(context: BaseRequestContext) -> None:  # noqa: C901 - Splitting this method adds unnecessary complexity
        """Respond to an EST enrollment message with the issued certificate."""
        if not isinstance(context, EstCertificateRequestContext):
            exc_msg = 'EstCertificateMessageResponder requires an EstCertificateRequestContext.'
            raise TypeError(exc_msg)

        if not EstCertificateMessageResponder._check_workflow_state(context):
            return
        if context.issued_certificate is None:
            exc_msg = 'Issued certificate is not set in the context.'
            raise ValueError(exc_msg)

        encoding: Encoding = Encoding.PEM
        if context.est_encoding in {'der', 'base64_der', 'pkcs7'}:
            encoding = Encoding.DER

        if context.est_encoding == 'pkcs7':
            cert_bytes = pkcs7.serialize_certificates([context.issued_certificate], encoding=Encoding.DER)
        else:
            cert_bytes = context.issued_certificate.public_bytes(encoding=encoding)

        cert: str | bytes

        if context.est_encoding == 'der':
            # Raw DER format (non-standard, for compatibility)
            cert = cert_bytes
            content_type = 'application/pkix-cert'
        elif context.est_encoding == 'pem':
            # PEM format (non-standard, for compatibility)
            try:
                cert = cert_bytes.decode('utf-8')
            except UnicodeDecodeError:
                cert = cert_bytes
            content_type = 'application/x-pem-file'
        else:
            # Default to RFC 7030 compliant format: base64-encoded with line wrapping
            # This includes 'base64_der', 'pkcs7', and any unspecified encoding
            b64_cert = base64.b64encode(cert_bytes).decode('utf-8')
            cert = '\n'.join([b64_cert[i:i + 64] for i in range(0, len(b64_cert), 64)])
            if context.est_encoding == 'base64_der':
                # base64_der is provided for compatibility with practical implementations
                content_type = 'application/pkix-cert'
            else:
                # PKCS#7 is the RFC 7030 compliant format (default)
                content_type = 'application/pkcs7-mime; smime-type=certs-only'

        if context.device and context.device.onboarding_config:
            context.device.onboarding_config.onboarding_status = OnboardingStatus.ONBOARDED
            context.device.onboarding_config.save()
        context.http_response_status = 200
        context.http_response_content = cert
        context.http_response_content_type = content_type


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
