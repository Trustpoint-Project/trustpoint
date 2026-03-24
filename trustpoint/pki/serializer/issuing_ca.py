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


class IssuingCaImportSerializer(serializers.Serializer[CaModel]):
    """Serializer for importing an Issuing CA from separate PEM-encoded files."""

    unique_name = serializers.CharField(
        required=False,
        allow_blank=True,
        default='',
        help_text='Optional unique name for the Issuing CA. Derived from the certificate CN if omitted.',
    )
    private_key_pem = serializers.CharField(
        help_text='PEM-encoded private key (PKCS#1, PKCS#8, or SEC1 for EC keys).',
        style={'base_template': 'textarea.html'},
    )
    private_key_password = serializers.CharField(
        required=False,
        allow_blank=True,
        default='',
        help_text='Optional password for an encrypted private key.',
        style={'input_type': 'password'},
    )
    ca_certificate_pem = serializers.CharField(
        help_text='PEM-encoded Issuing CA certificate.',
        style={'base_template': 'textarea.html'},
    )
    certificate_chain_pem = serializers.CharField(
        required=False,
        allow_blank=True,
        default='',
        help_text='Optional PEM-encoded certificate chain (intermediate + root CAs, concatenated).',
        style={'base_template': 'textarea.html'},
    )
