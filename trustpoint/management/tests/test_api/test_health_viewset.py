# Copyright (c) 2025 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Tests for HealthViewSet API endpoints.

The HealthViewSet provides a simple health check endpoint:
  GET  /api/health/  — returns system health status and database connectivity
"""

from unittest.mock import patch

import pytest
from django.db import DatabaseError
from rest_framework import status
from rest_framework.test import APIClient


HEALTH_URL = '/api/health/'


@pytest.fixture
def api_client() -> APIClient:
    """Return an unauthenticated API client."""
    return APIClient()


@pytest.mark.django_db
class TestHealthViewSet:
    """Test health check endpoint."""

    def test_health_check_success(self, api_client: APIClient) -> None:
        """Health check returns 200 with healthy status when database is accessible."""
        response = api_client.get(HEALTH_URL)
        
        assert response.status_code == status.HTTP_200_OK
        assert response.data['status'] == 'healthy'
        assert response.data['database'] == 'connected'

    def test_health_check_no_authentication_required(self, api_client: APIClient) -> None:
        """Health check endpoint does not require authentication."""
        response = api_client.get(HEALTH_URL)
        
        assert response.status_code != status.HTTP_401_UNAUTHORIZED
        assert response.status_code == status.HTTP_200_OK

    @patch('django.db.connection.cursor')
    def test_health_check_database_failure(
        self,
        mock_cursor,
        api_client: APIClient
    ) -> None:
        """Health check returns 503 when database connection fails."""
        mock_cursor.side_effect = DatabaseError('Connection failed')
        
        response = api_client.get(HEALTH_URL)
        
        assert response.status_code == status.HTTP_503_SERVICE_UNAVAILABLE
        assert response.data['status'] == 'unhealthy'
        assert response.data['database'] == 'disconnected'
        assert 'error' in response.data
