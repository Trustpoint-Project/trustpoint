# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Serializer for external audit log ingestion."""

from __future__ import annotations

from typing import Any, ClassVar

from rest_framework import serializers

from management.models.audit_log import AuditLog


class AuditLogIngestSerializer(serializers.ModelSerializer[AuditLog]):
    """Accept an external event and append it to the audit chain."""

    details = serializers.DictField(required=False, default=dict)

    class Meta:
        """Expose the input fields plus the immutable chain metadata in responses."""

        model = AuditLog
        fields = ('sequence', 'timestamp', 'operation_type', 'target_display', 'details', 'entry_hash')
        read_only_fields = ('sequence', 'timestamp', 'operation_type', 'entry_hash')
        extra_kwargs: ClassVar[dict[str, dict[str, Any]]] = {
            'target_display': {'required': False, 'allow_blank': True},
        }

    def create(self, validated_data: dict[str, Any]) -> AuditLog:
        """Store the event as an external entry attributed to the authenticated caller."""
        request = self.context['request']
        return AuditLog.objects.create(
            operation_type=AuditLog.OperationType.EXTERNAL_EVENT,
            target_display=validated_data.get('target_display') or f'External: {request.user}',
            actor=request.user,
            details=validated_data.get('details', {}),
        )
