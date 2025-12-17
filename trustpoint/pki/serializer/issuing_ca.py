"""Serializers for Issuing CA-related API endpoints.

Defines classes that handle validation and transformation
of Issuing CA model instances to and from JSON.
"""

from typing import ClassVar

from rest_framework import serializers

from pki.models.issuing_ca import IssuingCaModel


class IssuingCaSerializer(serializers.ModelSerializer[IssuingCaModel]):
    """Serializer for Issuing CA instances."""

    common_name = serializers.CharField(read_only=True)
    issuing_ca_type_display = serializers.CharField(
        source='get_issuing_ca_type_display',
        read_only=True
    )
    has_crl = serializers.SerializerMethodField()

    class Meta:
        """Metadata for IssuingCaSerializer, defining model and serialized fields."""

        model = IssuingCaModel
        fields: ClassVar[list[str]] = [
            'id',
            'unique_name',
            'common_name',
            'issuing_ca_type',
            'issuing_ca_type_display',
            'is_active',
            'created_at',
            'updated_at',
            'last_crl_issued_at',
            'has_crl',
        ]
        read_only_fields: ClassVar[list[str]] = [
            'id',
            'unique_name',
            'common_name',
            'issuing_ca_type',
            'issuing_ca_type_display',
            'is_active',
            'created_at',
            'updated_at',
            'last_crl_issued_at',
            'has_crl',
        ]

    def get_has_crl(self, obj: IssuingCaModel) -> bool:
        """Check if the Issuing CA has a CRL available."""
        return bool(obj.crl_pem)
