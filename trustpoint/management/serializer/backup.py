"""Serializers for Backup-related API endpoints.

Defines classes that handle validation and transformation
of Backup model instances to and from JSON.
"""

from typing import ClassVar

from rest_framework import serializers

from management.models import BackupOptions


class BackupSerializer(serializers.ModelSerializer):
    """Serializer for Backup instances.

    Handles conversion between Backup model objects and JSON representations.
    """

    class Meta:
        """Metadata for BackupSerializer, defining model and serialized fields."""

        model = BackupOptions
        fields: ClassVar[list[str]] = ['id', 'remote_directory']
        read_only_fields: ClassVar[list[str]] = ['id']
