"""DRF API views for REST PKI certificate enrollment."""

from __future__ import annotations

import json
import re
from io import BytesIO
from typing import TYPE_CHECKING, cast

from django.http import HttpRequest
from drf_spectacular.utils import OpenApiResponse, extend_schema
from rest_framework import status
from rest_framework.parsers import JSONParser
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from devices.models import DeviceModel
from request.authorization import RestAuthorization
from request.message_parser import RestMessageParser
from request.message_responder import RestErrorMessageResponder, RestMessageResponder
from request.operation_processor.general import OperationProcessor
from request.request_context import RestCertificateRequestContext
from request.request_validator import RestHttpRequestValidator
from request.workflows2_handler import Workflow2Handler
from trustpoint.logger import LoggerMixin
from workflows2.events.request_events import Events

from .serializers import CertificateEnrollRequestSerializer, CertificateEnrollResponseSerializer

if TYPE_CHECKING:
    from rest_framework.request import Request


def _sanitise_json_body(raw: bytes) -> bytes:
    r"""Replace literal newlines inside JSON string values with escaped ``\n`` sequences.

    DRF's :class:`~rest_framework.parsers.JSONParser` (and the stdlib
    :func:`json.loads`) reject raw control characters (including ``0x0A``
    newline) inside JSON string values, which is correct per RFC 7159.
    However, Swagger UI and some ``curl`` invocations embed PEM blocks with
    literal newlines in the JSON body, making the payload technically invalid.

    This helper performs a best-effort sanitisation pass: for every JSON
    string value in the body it escapes bare ``\n`` and ``\r`` characters so
    that the subsequent JSON parse succeeds.

    The replacement is done inside string literals only (between unescaped
    double-quotes), leaving structural JSON characters untouched.

    Args:
        raw: The raw request body bytes.

    Returns:
        Sanitised body bytes suitable for :func:`json.loads`.
    """
    # Replace literal newlines/carriage-returns that appear inside JSON string
    # literals.  We use a simple state-machine-style regex: match the content
    # between double-quote delimiters (non-greedy) and replace bare control
    # chars within each match.  This is intentionally conservative and only
    # targets the most common PEM-embedding pattern.
    try:
        text = raw.decode('utf-8')
    except UnicodeDecodeError:
        return raw

    def _escape_string_content(m: re.Match[str]) -> str:
        inner = m.group(1)
        inner = inner.replace('\r\n', '\\n').replace('\r', '\\n').replace('\n', '\\n')
        return f'"{inner}"'

    sanitised = re.sub(r'"((?:[^"\\]|\\.)*)"', _escape_string_content, text, flags=re.DOTALL)
    return sanitised.encode('utf-8')


class LenientJSONParser(JSONParser):
    """JSON parser that tolerates literal newlines inside string values.

    Before delegating to the standard DRF JSON parser this parser sanitises
    the request body so that PEM-encoded values with bare newline characters
    do not cause a ``JSON parse error``.
    """

    def parse(  # type: ignore[override]
        self,
        stream: BytesIO,
        media_type: str | None = None,
        parser_context: dict[str, object] | None = None,
    ) -> object:
        """Parse the stream, sanitising literal newlines in string values first."""
        raw = stream.read()
        sanitised = _sanitise_json_body(raw)
        return super().parse(BytesIO(sanitised), media_type, parser_context)


def _build_synthetic_request(csr_value: str) -> HttpRequest:
    """Build a minimal Django HttpRequest containing a JSON body with the given CSR."""
    synthetic = HttpRequest()
    synthetic.method = 'POST'
    synthetic.META['SERVER_NAME'] = 'localhost'
    synthetic.META['SERVER_PORT'] = '443'
    synthetic.META['CONTENT_TYPE'] = 'application/json'
    synthetic._body = json.dumps({'csr': csr_value}).encode()  # noqa: SLF001
    return synthetic


def _resolve_device(device_id: int) -> DeviceModel | Response:
    """Look up a device by primary key and return it or a 404 Response."""
    try:
        return DeviceModel.objects.select_related(
            'domain', 'onboarding_config', 'no_onboarding_config'
        ).get(pk=device_id)
    except DeviceModel.DoesNotExist:
        return Response(
            {'detail': f'Device with id {device_id} not found.'},
            status=status.HTTP_404_NOT_FOUND,
        )


def _validate_no_onboarding_device(device: DeviceModel) -> Response | None:
    """Validate that the device is a no-onboarding device with a domain."""
    if device.onboarding_config is not None:
        return Response(
            {'detail': 'Certificate enrollment via this API is only allowed for no-onboarding devices.'},
            status=status.HTTP_403_FORBIDDEN,
        )
    if device.no_onboarding_config is None:
        return Response(
            {'detail': 'Device has neither an onboarding nor a no-onboarding configuration.'},
            status=status.HTTP_400_BAD_REQUEST,
        )
    if device.domain is None:
        return Response(
            {'detail': 'Device is not associated with a domain.'},
            status=status.HTTP_400_BAD_REQUEST,
        )
    return None


@extend_schema(tags=['REST PKI'])
class ApplicationCertificateEnrollView(LoggerMixin, APIView):
    """Issue an application certificate for a no-onboarding device."""

    permission_classes = (IsAuthenticated,)
    parser_classes = (LenientJSONParser,)

    @extend_schema(
        summary='Issue an application certificate for a no-onboarding device',
        request=CertificateEnrollRequestSerializer,
        responses={
            200: CertificateEnrollResponseSerializer,
            400: OpenApiResponse(description='Bad Request - validation error or malformed CSR'),
            403: OpenApiResponse(description='Forbidden - device has an onboarding config'),
            404: OpenApiResponse(description='Not Found - device or domain does not exist'),
            500: OpenApiResponse(description='Internal Server Error - certificate issuance failed'),
        },
    )
    def post(self, request: Request) -> Response:
        """Issue an application certificate for a no-onboarding device."""
        serializer = CertificateEnrollRequestSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        device_id: int = serializer.validated_data['device_id']
        cert_profile: str = serializer.validated_data['cert_profile']
        csr_value: str = serializer.validated_data['csr']

        device_or_response = _resolve_device(device_id)
        if isinstance(device_or_response, Response):
            return device_or_response
        device = device_or_response

        validation_error = _validate_no_onboarding_device(device)
        if validation_error is not None:
            return validation_error

        domain = device.domain
        if domain is None:
            return Response(
                {'detail': 'Device is not associated with a domain.'},
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            ctx = RestCertificateRequestContext(
                raw_message=_build_synthetic_request(csr_value),
                protocol='rest',
                operation='enroll',
                domain_str=domain.unique_name,
                cert_profile_str=cert_profile,
                event=Events.rest_enroll,
                device=device,
            )
        except Exception:
            self.logger.exception('Failed to build REST certificate request context')
            return Response(
                {'detail': 'Failed to initialise the enrollment context.'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

        return self._run_enrollment_pipeline(ctx, device, device_id)

    def _run_enrollment_pipeline(
        self,
        ctx: RestCertificateRequestContext,
        device: DeviceModel,
        device_id: int,
    ) -> Response:
        """Run the REST PKI enrollment pipeline and return a DRF Response."""
        try:
            RestHttpRequestValidator().validate(ctx)
            ctx = cast('RestCertificateRequestContext', RestMessageParser().parse(ctx))
            ctx.device = device
            RestAuthorization(allowed_operations=['enroll']).authorize(ctx)
            Workflow2Handler().handle(ctx)
            OperationProcessor().process_operation(ctx)
            RestMessageResponder.build_response(ctx)
        except Exception:
            self.logger.exception('Error during API certificate enrollment for device %s', device_id)
            RestErrorMessageResponder.build_response(ctx)

        http_response = ctx.to_http_response()

        try:
            body = json.loads(http_response.content)
        except (ValueError, AttributeError):
            body = {'detail': http_response.content.decode('utf-8', errors='replace')}

        drf_status = http_response.status_code or status.HTTP_500_INTERNAL_SERVER_ERROR
        return Response(body, status=drf_status)
