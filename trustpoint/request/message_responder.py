"""Responds to the PKI message according to the original request protocol."""
import base64
from abc import ABC, abstractmethod

from cryptography.hazmat.primitives._serialization import Encoding

from request.request_context import RequestContext


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
        if context.issued_certificate and context.operation in ['simpleenroll', 'simplereenroll']:
            responder = EstCertificateMessageResponder()
            return responder.build_response(context)

        exc_msg = 'No suitable responder found for this EST message.'
        context.http_response_status = 500
        context.http_response_content = exc_msg
        return EstErrorMessageResponder().build_response(context)


class EstCertificateMessageResponder(EstMessageResponder):
    """Respond to an EST enrollment message with the issued certificate."""

    @staticmethod
    def build_response(context: RequestContext) -> None:
        """Respond to an EST enrollment message with the issued certificate."""
        if context.issued_certificate is None:
            exc_msg = 'Issued certificate is not set in the context.'
            raise ValueError(exc_msg)

        encoding = Encoding.DER if context.est_encoding in {'der', 'base64_der'} else Encoding.PEM
        cert_bytes = context.issued_certificate.public_bytes(encoding=encoding)

        if context.est_encoding == 'base64_der':
            b64_cert = base64.b64encode(cert_bytes).decode('utf-8')
            cert = '\n'.join([b64_cert[i:i + 64] for i in range(0, len(b64_cert), 64)])
            content_type = 'application/pkix-cert'
        elif context.est_encoding == 'der':
            cert = cert_bytes
            content_type = 'application/pkix-cert'
        else:
            try:
                cert = cert_bytes.decode('utf-8')
            except UnicodeDecodeError:
                cert = cert_bytes
            content_type = 'application/x-pem-file'

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


class CmpMessageResponder(AbstractMessageResponder):
    """Builds response to CMP requests."""

    @staticmethod
    def build_response(context: RequestContext) -> None:
        """Respond to a CMP message."""
        if context.issued_certificate and context.operation == 'initialization':
            responder = CmpInitializationResponder()
            return responder.build_response(context)

        exc_msg = 'No suitable responder found for this CMP message.'
        context.http_response_status = 500
        context.http_response_content = exc_msg
        return CmpErrorMessageResponder().build_response(context)


class CmpInitializationResponder(CmpMessageResponder):
    """Respond to a CMP initialization request with the issued certificate."""

    @staticmethod
    def build_response(context: RequestContext) -> None:
        """Respond to a CMP initialization message with the issued certificate."""
        if context.issued_certificate is None:
            exc_msg = 'Issued certificate is not set in the context.'
            raise ValueError(exc_msg)

        context.http_response_status = 200
        context.http_response_content = 'TODO'
        context.http_response_content_type = 'application/pkixcmp'


class CmpErrorMessageResponder(CmpMessageResponder):
    """Respond to a CMP message with an error."""

    @staticmethod
    def build_response(context: RequestContext) -> None:
        """Respond to a CMP message with an error."""
        # Set appropriate HTTP status code and error message in context
        # TODO(Air): Use CMP error message format instead of plain text
        context.http_response_status = context.http_response_status or 500
        context.http_response_content = context.http_response_content or 'An error occurred processing the CMP request.'
        context.http_response_content_type = context.http_response_content_type or 'text/plain'
