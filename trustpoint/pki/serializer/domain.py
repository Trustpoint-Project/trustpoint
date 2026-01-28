"""Serializers for Domain-related API endpoints.

Defines classes that handle validation and transformation
of Domain model instances to and from JSON.
"""

from typing import ClassVar

from rest_framework import serializers

from pki.models.domain import DomainModel


class DomainSerializer(serializers.ModelSerializer[DomainModel]):
    """Serializer for Domain instances.

    Handles conversion between Domain model objects and JSON representations.
    """

    class Meta:
        """Metadata for DomainSerializer, defining model and serialized fields."""

        model = DomainModel
        fields: ClassVar[list[str]] = ['id', 'unique_name']
        read_only_fields: ClassVar[list[str]] = ['id']
