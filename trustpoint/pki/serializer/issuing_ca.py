"""Serializers for Issuing CA-related API endpoints.

Defines classes that handle validation and transformation
of Issuing CA model instances to and from JSON.
"""

from typing import ClassVar

from rest_framework import serializers

from pki.models import CaModel


class IssuingCaSerializer(serializers.ModelSerializer[CaModel]):
    """Serializer for Issuing CA instances."""

    common_name = serializers.SerializerMethodField()
    ca_type = serializers.CharField(read_only=True)
    ca_type_display = serializers.CharField(
        source='get_ca_type_display',
        read_only=True
    )
    last_crl_issued_at = serializers.SerializerMethodField()
    has_crl = serializers.SerializerMethodField()

    class Meta:
        """Metadata for IssuingCaSerializer, defining model and serialized fields."""

        model = CaModel
        fields: ClassVar[list[str]] = [
            'id',
            'unique_name',
            'common_name',
            'ca_type',
            'ca_type_display',
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
            'ca_type',
            'ca_type_display',
            'is_active',
            'created_at',
            'updated_at',
            'last_crl_issued_at',
            'has_crl',
        ]

    def get_has_crl(self, obj: CaModel) -> bool:
        """Check if the CA has a CRL available."""
        return bool(obj.crl_pem)

    def get_last_crl_issued_at(self, obj: CaModel) -> str | None:
        """Get the last CRL issued at timestamp."""
        timestamp = obj.last_crl_issued_at
        return timestamp.isoformat() if timestamp else None

    def get_common_name(self, obj: CaModel) -> str:
        """Get the common name of the CA."""
        return obj.common_name
