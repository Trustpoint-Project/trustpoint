# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Tests for the external audit log ingestion endpoint."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APIClient

from management.models.audit_log import AuditLog

if TYPE_CHECKING:
    from users.models import TrustpointUser

User = get_user_model()


@pytest.fixture
def api_client() -> APIClient:
    """Return an unauthenticated API client."""
    return APIClient()


@pytest.fixture
def user() -> TrustpointUser:
    """Create a user allowed to append external audit entries."""
    test_user = User.objects.create_user(username='audit-ingest')
    test_user.role.permissions.add(Permission.objects.get(codename='add_audit_log'))
    return test_user


@pytest.mark.django_db
class TestAuditLogViewSet:
    """Test POST /api/audit-logs/."""

    def test_requires_authentication(self, api_client: APIClient) -> None:
        """Anonymous requests are rejected."""
        response = api_client.post(reverse('audit-log-list'), {'details': {'event': 'x'}}, format='json')
        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    def test_requires_add_permission(self, api_client: APIClient) -> None:
        """Authenticated users without the append permission are rejected."""
        plain_user = User.objects.create_user(username='audit-plain')
        api_client.force_authenticate(user=plain_user)
        response = api_client.post(reverse('audit-log-list'), {'details': {'event': 'x'}}, format='json')
        assert response.status_code == status.HTTP_403_FORBIDDEN

    def test_appends_external_entry(self, api_client: APIClient, user: TrustpointUser) -> None:
        """The event is stored in the hash chain and attributed to the caller."""
        api_client.force_authenticate(user=user)
        response = api_client.post(
            reverse('audit-log-list'),
            {'target_display': 'Billing system', 'details': {'action': 'invoice', 'id': 42}},
            format='json',
        )
        assert response.status_code == status.HTTP_201_CREATED, response.data
        entry = AuditLog.objects.get(sequence=response.data['sequence'])
        assert entry.operation_type == AuditLog.OperationType.EXTERNAL_EVENT
        assert entry.actor == user
        assert entry.target_display == 'Billing system'
        assert entry.details == {'action': 'invoice', 'id': 42}
        assert entry.entry_hash == entry.calculate_entry_hash()

    def test_omitted_fields_use_defaults(self, api_client: APIClient, user: TrustpointUser) -> None:
        """Without a label or details, the actor and an empty payload are recorded."""
        api_client.force_authenticate(user=user)
        response = api_client.post(reverse('audit-log-list'), {}, format='json')
        assert response.status_code == status.HTTP_201_CREATED, response.data
        assert response.data['target_display'] == f'External: {user}'
        assert response.data['details'] == {}

    def test_details_must_be_an_object(self, api_client: APIClient, user: TrustpointUser) -> None:
        """A non-object JSON payload is rejected before touching the chain."""
        api_client.force_authenticate(user=user)
        response = api_client.post(reverse('audit-log-list'), {'details': ['not', 'an', 'object']}, format='json')
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert not AuditLog.objects.exists()
