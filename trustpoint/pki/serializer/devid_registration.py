"""Serializers for DevIdRegistration-related API endpoints.

Defines classes that handle validation and transformation
of DevIdRegistration model instances to and from JSON.
"""

from typing import ClassVar

from rest_framework import serializers

from pki.models.devid_registration import DevIdRegistration
from util.field import UniqueNameValidator


class DevIdRegistrationSerializer(serializers.ModelSerializer[DevIdRegistration]):
    """Serializer for DevIdRegistration instances.

    Handles conversion between DevIdRegistration model objects and JSON representations.
    """

    unique_name = serializers.CharField(
        max_length=256,
        required=False,
        allow_blank=True,
        help_text='Optional unique name. If omitted, the truststore name is used.',
        validators=[UniqueNameValidator()],
    )

    class Meta:
        """Metadata for DevIdRegistrationSerializer, defining model and serialized fields."""

        model = DevIdRegistration
        fields: ClassVar[list[str]] = ['id', 'unique_name', 'truststore', 'domain', 'serial_number_pattern']
        read_only_fields: ClassVar[list[str]] = ['id']


class DevIdRegistrationDetailSerializer(serializers.ModelSerializer[DevIdRegistration]):
    """Detailed serializer for a single DevIdRegistration instance.

    Includes related object names for readability.
    """

    truststore_name = serializers.CharField(source='truststore.unique_name', read_only=True)
    domain_name = serializers.CharField(source='domain.unique_name', read_only=True)

    class Meta:
        """Metadata for DevIdRegistrationDetailSerializer, defining model and serialized fields."""

        model = DevIdRegistration
        fields: ClassVar[list[str]] = [
            'id',
            'unique_name',
            'truststore',
            'truststore_name',
            'domain',
            'domain_name',
            'serial_number_pattern',
        ]
        read_only_fields: ClassVar[list[str]] = ['id', 'truststore_name', 'domain_name']
