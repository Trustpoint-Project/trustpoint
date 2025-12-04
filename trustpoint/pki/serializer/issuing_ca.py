"""Serializers for Issuing CA-related API endpoints.

Defines classes that handle validation and transformation
of Issuing CA model instances to and from JSON.
"""

from typing import ClassVar

from rest_framework import serializers

from pki.models.issuing_ca import IssuingCaModel


class IssuingCaSerializer(serializers.ModelSerializer):
    """Serializer for Issuing CA instances.

    Handles conversion between Issuing CA model objects and JSON representations.
    """

    class Meta:
        """Metadata for DomainSerializer, defining model and serialized fields."""

        model = IssuingCaModel
        fields: ClassVar[list[str]] = ['id', 'unique_name', 'is_active']
        read_only_fields: ClassVar[list[str]] = ['id']
