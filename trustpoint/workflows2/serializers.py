"""Serializers for Workflow 2 API endpoints."""

from __future__ import annotations

from rest_framework import serializers

from workflows2.models import Workflow2Definition


class Workflow2DefinitionSerializer(serializers.ModelSerializer[Workflow2Definition]):
    """Serialize persisted Workflow 2 definitions."""

    class Meta:
        """Serializer metadata."""

        model = Workflow2Definition
        fields = (
            'id',
            'name',
            'enabled',
            'trigger_on',
            'yaml_text',
            'ir_json',
            'ir_hash',
            'created_at',
        )
        read_only_fields = ('id', 'trigger_on', 'ir_json', 'ir_hash', 'created_at')
