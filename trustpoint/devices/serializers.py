"""Serializers for Device-related API endpoints.

Defines classes that handle validation and transformation
of Device model instances to and from JSON.
"""

from rest_framework import serializers

from .models import DeviceModel


class DeviceSerializer(serializers.ModelSerializer):
    """Serializer for Device instances.

    Handles conversion between Device model objects and JSON representations.
    """

    class Meta:
        """Metadata for DeviceSerializer, defining model and serialized fields."""

        model = DeviceModel
        fields = '__all__'
