"""EST-specific message responder classes."""
import base64

from cryptography.hazmat.primitives.serialization import Encoding, pkcs7

from devices.models import OnboardingStatus
from request.request_context import EstBaseRequestContext, EstCertificateRequestContext
from workflows.models import State

from .base import AbstractMessageResponder


class EstMessageResponder(AbstractMessageResponder):
    """Builds response to EST requests."""

    @staticmethod
    def build_response(context: EstBaseRequestContext) -> None:
        """Respond to an EST message."""
        if not context.enrollment_request:
            exc_msg = 'No enrollment request is set in the context.'
            raise ValueError(exc_msg)

        workflow_state = context.enrollment_request.aggregated_state
        if workflow_state == State.AWAITING:
            context.http_response_status = 202
            context.http_response_content_type = 'text/plain'
            context.http_response_content = 'Enrollment request pending manual approval.'
            # TODO(Air): Implement Retry-After header  # noqa: FIX002
            return None
        if workflow_state == State.REJECTED:
            context.enrollment_request.finalize(State.REJECTED)
            context.http_response_status = 403
            context.http_response_content_type = 'text/plain'
            context.http_response_content = 'Enrollment request Rejected.'
            return None
        if workflow_state == State.FAILED:
            context.http_response_status = 500
            context.http_response_content_type = 'text/plain'
            context.http_response_content = \
                f'Workflow failed. Check here: -> /workflows/requests/{context.enrollment_request.id}'
            return None
        if context.enrollment_request.is_valid() and context.operation in ['simpleenroll', 'simplereenroll']:
            responder = EstCertificateMessageResponder()
            context.enrollment_request.finalize(State.FINALIZED)
            return responder.build_response(context)
        exc_msg = 'No suitable responder found for this EST message.'
        context.http_response_status = 500
        context.http_response_content = exc_msg
        return EstErrorMessageResponder().build_response(context)


class EstCertificateMessageResponder(EstMessageResponder):
    """Respond to an EST enrollment message with the issued certificate."""

    @staticmethod
    def build_response(context: EstCertificateRequestContext) -> None:
        """Respond to an EST enrollment message with the issued certificate."""
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

        if context.est_encoding == 'base64_der':
            b64_cert = base64.b64encode(cert_bytes).decode('utf-8')
            cert = '\n'.join([b64_cert[i:i + 64] for i in range(0, len(b64_cert), 64)])
            content_type = 'application/pkix-cert'
        elif context.est_encoding == 'der':
            cert = cert_bytes
            content_type = 'application/pkix-cert'
        elif context.est_encoding == 'pkcs7':
            # this is the only type compliant with RFC 7030
            # others are only provided for compatibility with practical implementations
            cert = cert_bytes
            content_type = 'application/pkcs7-mime; smime-type=certs-only'
        else:
            try:
                cert = cert_bytes.decode('utf-8')
            except UnicodeDecodeError:
                cert = cert_bytes
            content_type = 'application/x-pem-file'

        if context.device and context.device.onboarding_config:
            context.device.onboarding_config.onboarding_status = OnboardingStatus.ONBOARDED
            context.device.onboarding_config.save()
        context.http_response_status = 200
        context.http_response_content = cert
        context.http_response_content_type = content_type


class EstErrorMessageResponder(EstMessageResponder):
    """Respond to an EST message with an error."""

    @staticmethod
    def build_response(context: EstBaseRequestContext) -> None:
        """Respond to an EST message with an error."""
        # Set appropriate HTTP status code and error message in context
        context.http_response_status = context.http_response_status or 500
        context.http_response_content = context.http_response_content or 'An error occurred processing the EST request.'
        context.http_response_content_type = context.http_response_content_type or 'text/plain'
