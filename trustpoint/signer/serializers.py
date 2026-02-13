"""Serializers for Signer-related API endpoints."""

from typing import Any, ClassVar

from rest_framework import serializers

from signer.models import SignedMessageModel, SignerModel


class SignerSerializer(serializers.ModelSerializer[SignerModel]):
    """Serializer for Signer instances."""

    certificate_cn = serializers.CharField(source='credential.certificate.common_name', read_only=True, allow_null=True)
    certificate_not_valid_after = serializers.DateTimeField(
        source='credential.certificate.not_valid_after', read_only=True
    )
    signature_suite = serializers.CharField(source='credential.certificate.signature_suite', read_only=True)

    class Meta:
        """Metadata for SignerSerializer, defining model and serialized fields."""

        model = SignerModel
        fields: ClassVar[list[str]] = [
            'id',
            'unique_name',
            'certificate_cn',
            'certificate_not_valid_after',
            'signature_suite',
            'created_at',
            'updated_at',
        ]
        read_only_fields: ClassVar[list[str]] = fields


class SignHashRequestSerializer(serializers.Serializer[Any]):
    """Serializer for sign hash request."""

    signer_id = serializers.IntegerField(required=True, help_text='The ID of the signer to use for signing')
    hash_value = serializers.CharField(
        required=True, max_length=128, help_text='The hash value to sign (hexadecimal string)'
    )

    def validate_signer_id(self, value: int) -> int:
        """Validate that the signer exists."""
        if not SignerModel.objects.filter(id=value).exists():
            msg = f'Signer with ID {value} does not exist.'
            raise serializers.ValidationError(msg)
        return value

    def validate_hash_value(self, value: str) -> str:
        """Validate that the hash value is a valid hexadecimal string."""
        try:
            bytes.fromhex(value)
        except ValueError as e:
            msg = 'Hash value must be a valid hexadecimal string.'
            raise serializers.ValidationError(msg) from e

        return value.lower()


class SignHashResponseSerializer(serializers.Serializer[Any]):
    """Serializer for sign hash response."""

    signer_id = serializers.IntegerField(read_only=True, help_text='The ID of the signer used')
    signer_name = serializers.CharField(read_only=True, help_text='The unique name of the signer')
    hash_algorithm = serializers.CharField(read_only=True, help_text='The hash algorithm used by the signer')
    hash_value = serializers.CharField(read_only=True, help_text='The hash value that was signed')
    signature = serializers.CharField(read_only=True, help_text='The signature in hexadecimal format')
    signed_message_id = serializers.IntegerField(
        read_only=True, help_text='The ID of the created signed message record'
    )
    created_at = serializers.DateTimeField(read_only=True, help_text='Timestamp when the signature was created')


class SignerCertificateSerializer(serializers.Serializer[Any]):
    """Serializer for signer certificate response."""

    signer_id = serializers.IntegerField(read_only=True, help_text='The ID of the signer')
    signer_name = serializers.CharField(read_only=True, help_text='The unique name of the signer')
    certificate_pem = serializers.CharField(read_only=True, help_text='The PEM-encoded certificate')


class SignedMessageSerializer(serializers.ModelSerializer[SignedMessageModel]):
    """Serializer for SignedMessage instances."""

    signer_name = serializers.CharField(source='signer.unique_name', read_only=True)

    class Meta:
        """Metadata for SignedMessageSerializer, defining model and serialized fields."""

        model = SignedMessageModel
        fields: ClassVar[list[str]] = [
            'id',
            'signer',
            'signer_name',
            'hash_value',
            'signature',
            'created_at',
        ]
        read_only_fields = fields
