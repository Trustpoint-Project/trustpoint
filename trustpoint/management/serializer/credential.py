"""Serializers for Credential-related API endpoints.

Defines classes that handle validation and transformation
of Credential model instances to and from JSON.
"""

from typing import ClassVar

from rest_framework import serializers

from pki.models.credential import CredentialModel


class CredentialSerializer(serializers.ModelSerializer):
    """Serializer for Credential instances.

    Handles conversion between Credential model objects and JSON representations.
    """

    class Meta:
        """Metadata for CredentialSerializer, defining model and serialized fields."""

        model = CredentialModel
        fields: ClassVar[list[str]] = ['id', 'credential_type', 'created_at']
        read_only_fields: ClassVar[list[str]] = ['id']
