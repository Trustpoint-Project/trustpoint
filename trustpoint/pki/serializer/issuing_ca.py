"""Serializers for Issuing CA-related API endpoints.

Defines classes that handle validation and transformation
of Issuing CA model instances to and from JSON.
"""

from typing import ClassVar

from rest_framework import serializers

from pki.models.ca import CaModel


class IssuingCaSerializer(serializers.ModelSerializer[CaModel]):
    """Serializer for Issuing CA instances."""

    common_name = serializers.SerializerMethodField()
    issuing_ca_type = serializers.CharField(source='issuing_ca_ref.issuing_ca_type', read_only=True)
    issuing_ca_type_display = serializers.CharField(
        source='issuing_ca_ref.get_issuing_ca_type_display',
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

    def get_has_crl(self, obj: CaModel) -> bool:
        """Check if the Issuing CA has a CRL available."""
        return bool(obj.issuing_ca_ref.crl_pem)

    def get_last_crl_issued_at(self, obj: CaModel) -> str | None:
        """Get the last CRL issued at timestamp."""
        return obj.issuing_ca_ref.last_crl_issued_at

    def get_common_name(self, obj: CaModel) -> str:
        """Get the common name of the issuing CA."""
        return obj.issuing_ca_ref.common_name
