"""Serializers for Truststore-related API endpoints.

Defines classes that handle validation and transformation
of Truststore model instances to and from JSON.
"""

from typing import ClassVar, cast

from django.core.exceptions import ValidationError
from django.core.files.uploadedfile import UploadedFile
from rest_framework import serializers
from util.field import UniqueNameValidator

from pki.models.truststore import TruststoreModel


class TruststoreSerializer(serializers.ModelSerializer):
    """Serializer for Certificate instances.

    Handles conversion between Certificate model objects and JSON representations.
    """

    unique_name = serializers.CharField(
        max_length=256,
        required=False,
        allow_blank=True,
        help_text='Optional unique name',
        validators=[UniqueNameValidator()],
    )

    intended_usage = serializers.ChoiceField(
        choices=TruststoreModel.IntendedUsage, required=True, help_text='Intended usage for this truststore'
    )

    trust_store_file = serializers.FileField(write_only=True, required=True)

    class Meta:
        """Metadata for TruststoreSerializer, defining model and serialized fields."""

        model = TruststoreModel
        fields: ClassVar[list[str]] = ['id', 'unique_name', 'intended_usage', 'created_at', 'trust_store_file']
        read_only_fields: ClassVar[list[str]] = ['id']

    def validate_trust_store_file(self, file: UploadedFile) -> bytes:
        """Validate uploaded truststore file."""
        if not file:
            msg = 'Truststore file is required.'
            raise ValidationError(msg)
        if not file.name.lower().endswith(('.pem', '.p7b', '.p7c')):
            msg = 'File must be PEM or PKCS#7 format.'
            raise ValidationError(msg)
        try:
            return cast('bytes', file.read())
        except (OSError, AttributeError) as original_exception:
            error_message = (
                'Unexpected error occurred while trying to get file contents. Please see logs for further details.'
            )
            raise ValidationError(error_message, code='unexpected-error') from original_exception
