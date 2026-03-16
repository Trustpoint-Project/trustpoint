"""DRF API views for the WBM agent endpoints."""
from __future__ import annotations

import json
from typing import TYPE_CHECKING

from drf_spectacular.utils import OpenApiResponse, extend_schema
from rest_framework import status
from rest_framework.parsers import JSONParser
from rest_framework.response import Response

from agents.views import AgentPipelineAPIView, AgentPipelineConfig
from agents.wbm.authorization import WbmPushResultAuthorization, WbmSubmitCsrAuthorization
from agents.wbm.message_parser import WbmCheckInParser, WbmPushResultParser, WbmSubmitCsrParser
from agents.wbm.message_responder import (
    WbmCheckInResponder,
    WbmErrorResponder,
    WbmPushResultResponder,
    WbmSubmitCsrResponder,
)
from agents.wbm.operation_processor.check_in import WbmCheckInProcessor
from agents.wbm.operation_processor.push_result import WbmPushResultProcessor
from agents.wbm.operation_processor.submit_csr import WbmSubmitCsrProcessor
from agents.wbm.request_context import WbmAgentRequestContext
from agents.wbm.serializers import (
    WbmCheckInResponseSerializer,
    WbmPushResultRequestSerializer,
    WbmPushResultResponseSerializer,
    WbmSubmitCsrRequestSerializer,
    WbmSubmitCsrResponseSerializer,
)

if TYPE_CHECKING:
    from rest_framework.request import Request


@extend_schema(tags=['Agents'])
class WbmCheckInView(AgentPipelineAPIView):
    """GET /api/agents/wbm/check-in/ — agent polls for pending work."""

    context_class = WbmAgentRequestContext

    @extend_schema(
        summary='Agent check-in: retrieve pending jobs',
        responses={
            200: WbmCheckInResponseSerializer,
            401: OpenApiResponse(description='Unauthorized - mTLS certificate not recognised'),
            403: OpenApiResponse(description='Forbidden - agent is inactive'),
            500: OpenApiResponse(description='Internal Server Error'),
        },
    )
    def get(self, request: Request) -> Response:
        """Handle agent check-in: authenticate and return any pending jobs."""
        return self._run_api_pipeline(
            request,
            operation='check-in',
            config=AgentPipelineConfig(
                parser=WbmCheckInParser(),
                extra_authorizers=[],
                processor=WbmCheckInProcessor(),
                responder=WbmCheckInResponder(),
                error_responder=WbmErrorResponder(),
            ),
        )


@extend_schema(tags=['Agents'])
class WbmSubmitCsrView(AgentPipelineAPIView):
    """POST /api/agents/wbm/submit-csr/ — agent submits a CSR for signing."""

    context_class = WbmAgentRequestContext
    parser_classes = (JSONParser,)

    @extend_schema(
        summary='Agent submit-csr: submit a CSR for a pending job',
        request=WbmSubmitCsrRequestSerializer,
        responses={
            200: WbmSubmitCsrResponseSerializer,
            400: OpenApiResponse(description='Bad Request - validation error or malformed CSR'),
            401: OpenApiResponse(description='Unauthorized - mTLS certificate not recognised'),
            403: OpenApiResponse(description='Forbidden - agent inactive or job ownership mismatch'),
            500: OpenApiResponse(description='Internal Server Error - certificate issuance failed'),
        },
    )
    def post(self, request: Request) -> Response:
        """Validate the request body and run the submit-csr pipeline."""
        serializer = WbmSubmitCsrRequestSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        # Re-encode validated (newline-normalised) data onto the underlying
        # Django request body so WbmSubmitCsrParser can read it as normal.
        request._request._body = json.dumps(serializer.validated_data).encode()  # noqa: SLF001

        return self._run_api_pipeline(
            request,
            operation='submit-csr',
            config=AgentPipelineConfig(
                parser=WbmSubmitCsrParser(),
                extra_authorizers=[WbmSubmitCsrAuthorization()],
                processor=WbmSubmitCsrProcessor(),
                responder=WbmSubmitCsrResponder(),
                error_responder=WbmErrorResponder(),
            ),
        )


@extend_schema(tags=['Agents'])
class WbmPushResultView(AgentPipelineAPIView):
    """POST /api/agents/wbm/push-result/ — agent reports the outcome of a push."""

    context_class = WbmAgentRequestContext
    parser_classes = (JSONParser,)

    @extend_schema(
        summary='Agent push-result: report the outcome of a certificate push',
        request=WbmPushResultRequestSerializer,
        responses={
            200: WbmPushResultResponseSerializer,
            400: OpenApiResponse(description='Bad Request - validation error'),
            401: OpenApiResponse(description='Unauthorized - mTLS certificate not recognised'),
            403: OpenApiResponse(description='Forbidden - agent inactive or job ownership mismatch'),
            500: OpenApiResponse(description='Internal Server Error'),
        },
    )
    def post(self, request: Request) -> Response:
        """Validate the request body and run the push-result pipeline."""
        serializer = WbmPushResultRequestSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        request._request._body = json.dumps(serializer.validated_data).encode()  # noqa: SLF001

        return self._run_api_pipeline(
            request,
            operation='push-result',
            config=AgentPipelineConfig(
                parser=WbmPushResultParser(),
                extra_authorizers=[WbmPushResultAuthorization()],
                processor=WbmPushResultProcessor(),
                responder=WbmPushResultResponder(),
                error_responder=WbmErrorResponder(),
            ),
        )

