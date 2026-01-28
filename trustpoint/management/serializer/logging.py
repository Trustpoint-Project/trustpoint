"""Serializers for logging-related API endpoints.

Defines classes that handle validation and transformation
of logging instance to and from JSON.
"""

from typing import Any

from rest_framework import serializers


class LoggingSerializer(serializers.Serializer[Any]):
    """Serializer for Logging instances.

    Handles conversion between Log files and JSON representations.
    """
    name = serializers.CharField()
    size = serializers.IntegerField()
    modified = serializers.DateTimeField()
