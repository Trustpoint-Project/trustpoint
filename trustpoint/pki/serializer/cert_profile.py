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
    Used for list, create, update, and partial_update actions.
    """

    class Meta:
        """Metadata for CertProfileSerializer, defining model and serialized fields."""

        model = CertificateProfileModel
        fields: ClassVar[list[str]] = ['id', 'unique_name', 'display_name', 'profile_json', 'is_default']
        read_only_fields: ClassVar[list[str]] = ['id']


class CertProfileDetailSerializer(serializers.ModelSerializer[CertificateProfileModel]):
    """Detailed serializer for a single Certificate Profile instance."""

    profile_json = serializers.SerializerMethodField()

    def get_profile_json(self, obj: CertificateProfileModel) -> object:
        """Return profile_json as a parsed JSON object."""
        return obj.profile

    class Meta:
        """Metadata for CertProfileDetailSerializer, defining model and serialized fields."""

        model = CertificateProfileModel
        fields: ClassVar[list[str]] = [
            'id',
            'unique_name',
            'display_name',
            'profile_json',
            'is_default',
            'created_at',
            'updated_at',
        ]
        read_only_fields: ClassVar[list[str]] = ['id', 'created_at', 'updated_at']
