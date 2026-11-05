# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Shared persistence hooks for audited REST API resources."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from django.db import transaction
from rest_framework import viewsets

from management.security_change_audit import audit_security_change, security_change

if TYPE_CHECKING:
    from django.db.models import Model


class AuditedModelViewSet[ModelT: Model](viewsets.ModelViewSet[ModelT]):
    """Audit creation, final persisted updates, and deletion at the API boundary."""

    @transaction.atomic
    def perform_create(self, serializer: Any) -> None:
        """Create and audit the object atomically."""
        target = serializer.save()
        audit_security_change(target=target, actor=self.request.user, before=None, action='created')

    def perform_update(self, serializer: Any) -> None:
        """Capture changes after serializer-managed relations have been saved."""
        with security_change(target=serializer.instance, actor=self.request.user):
            serializer.save()

    def perform_destroy(self, instance: Any) -> None:
        """Capture the object's identity and state before deletion."""
        with security_change(target=instance, actor=self.request.user, action='deleted'):
            instance.delete()
