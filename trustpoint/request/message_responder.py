"""Responds to the PKI message according to the original request protocol."""
import base64
from abc import ABC, abstractmethod

from cryptography.hazmat.primitives.serialization import Encoding, pkcs7

from devices.models import OnboardingStatus
from request.request_context import RequestContext
from workflows.models import State


class AbstractMessageResponder(ABC):
    """Abstract base class for message responders."""

    @staticmethod
    @abstractmethod
    def build_response(context: RequestContext) -> None:
        """Abstract base method for building a response to a message."""


class EstMessageResponder(AbstractMessageResponder):
    """Builds response to EST requests."""

    @staticmethod
    def build_response(context: RequestContext) -> None:
        """Respond to an EST message."""
        req = getattr(context, 'enrollment_request', None)
        if req is None:
            if context.operation in {'simpleenroll', 'simplereenroll'}:
                return EstCertificateMessageResponder().build_response(context)

            context.http_response_status = 500
            context.http_response_content_type = 'text/plain'
            context.http_response_content = 'No suitable responder found for this EST message.'
            return EstErrorMessageResponder().build_response(context)

        # Ensure we use the latest aggregated_state derived from child instances.
        # This is safe even if the handler already recomputed.
        req.recompute_and_save()
        req.refresh_from_db(fields=['aggregated_state', 'finalized', 'updated_at'])

        # Pending states: request exists but not yet approved.
        if req.aggregated_state in {State.AWAITING, State.RUNNING}:
            context.http_response_status = 202
            context.http_response_content_type = 'text/plain'
            context.http_response_content = 'Enrollment request pending manual approval.'
            # TODO(Air): Implement Retry-After header  # noqa: FIX002
            return None

        # Terminal negative outcomes.
        if req.aggregated_state == State.REJECTED:
            req.finalize(State.REJECTED)
            context.http_response_status = 403
            context.http_response_content_type = 'text/plain'
            context.http_response_content = 'Enrollment request rejected.'
            return None

        if req.aggregated_state == State.ABORTED:
            req.finalize(State.ABORTED)
            context.http_response_status = 409
            context.http_response_content_type = 'text/plain'
            context.http_response_content = 'Enrollment request aborted.'
            return None

        if req.aggregated_state == State.FAILED:
            context.http_response_status = 500
            context.http_response_content_type = 'text/plain'
            context.http_response_content = (
                f'Workflow failed. Check here: -> /workflows/requests/{req.id}'
            )
            return None

        # Approved/successful outcomes: issue only for supported operations.
        if req.is_valid() and context.operation in {'simpleenroll', 'simplereenroll'}:
            responder = EstCertificateMessageResponder()
            req.finalize(State.FINALIZED)
            return responder.build_response(context)

        # Unknown state or unsupported operation while gated by workflows.
        context.http_response_status = 500
        context.http_response_content_type = 'text/plain'
        context.http_response_content = 'No suitable responder found for this EST message.'
        return EstErrorMessageResponder().build_response(context)


class EstCertificateMessageResponder(EstMessageResponder):
    """Respond to an EST enrollment message with the issued certificate."""

    @staticmethod
    def build_response(context: RequestContext) -> None:
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
    def build_response(context: RequestContext) -> None:
        """Respond to an EST message with an error."""
        # Set appropriate HTTP status code and error message in context
        context.http_response_status = context.http_response_status or 500
        context.http_response_content = context.http_response_content or 'An error occurred processing the EST request.'
        context.http_response_content_type = context.http_response_content_type or 'text/plain'
