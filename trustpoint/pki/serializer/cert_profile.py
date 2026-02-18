"""Serializers for Certificate Profile-related API endpoints.

Defines classes that handle validation and transformation
of Certificate profile model instances to and from JSON.
"""

from typing import ClassVar

from rest_framework import serializers

from pki.models.cert_profile import CertificateProfileModel


class CertProfileSerializer(serializers.ModelSerializer[CertificateProfileModel]):
    """Serializer for Certificate profile instances.

    Handles conversion between Certificate Profile model objects and JSON representations.
    """

    class Meta:
        """Metadata for CertProfileSerializer, defining model and serialized fields."""

        model = CertificateProfileModel
        fields: ClassVar[list[str]] = ['id', 'unique_name']
        read_only_fields: ClassVar[list[str]] = ['id']
