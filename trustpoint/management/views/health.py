# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Health check views for monitoring Trustpoint Extension status."""

from typing import Any, ClassVar

from django.db import DatabaseError, connection
from drf_spectacular.utils import extend_schema
from rest_framework import status, viewsets
from rest_framework.permissions import AllowAny
from rest_framework.request import Request
from rest_framework.response import Response

from trustpoint.logger import LoggerMixin


@extend_schema(tags=['Health'])
class HealthViewSet(LoggerMixin, viewsets.GenericViewSet[Any]):
    """ViewSet for health check operations."""
    permission_classes: ClassVar = [AllowAny]  # type: ignore[misc]
    filter_backends: ClassVar = ()  # type: ignore[misc]

    @extend_schema(
        summary='Health check',
        description=(
            'Provides a simple connectivity and readiness check for the Trustpoint Extension. '
            'Verifies database connectivity and returns system status.'
        ),
        responses={
            200: {
                'type': 'object',
                'properties': {
                    'status': {'type': 'string', 'example': 'healthy'},
                    'database': {'type': 'string', 'example': 'connected'},
                },
            },
            503: {
                'type': 'object',
                'properties': {
                    'status': {'type': 'string', 'example': 'unhealthy'},
                    'database': {'type': 'string', 'example': 'disconnected'},
                    'error': {'type': 'string', 'example': 'Database connection failed'},
                },
            },
        }
    )
    def list(self, _request: Request) -> Response:
        """Perform a health check on the system."""
        try:
            with connection.cursor() as cursor:
                cursor.execute('SELECT 1')
                cursor.fetchone()

            return Response(
                {
                    'status': 'healthy',
                    'database': 'connected',
                },
                status=status.HTTP_200_OK,
            )
        except DatabaseError:
            self.logger.exception('Health check failed: database connection error')
            return Response(
                {
                    'status': 'unhealthy',
                    'database': 'disconnected',
                    'error': 'Database connection failed',
                },
                status=status.HTTP_503_SERVICE_UNAVAILABLE,
            )
