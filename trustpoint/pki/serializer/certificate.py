"""Serializers for Certificate-related API endpoints.

Defines classes that handle validation and transformation
of Certificate model instances to and from JSON.
"""

from typing import ClassVar

from rest_framework import serializers

from pki.models.certificate import CertificateModel


class CertificateSerializer(serializers.ModelSerializer[CertificateModel]):
    """Serializer for Certificate instances.

    Handles conversion between Certificate model objects and JSON representations.
    """

    class Meta:
        """Metadata for CertificateSerializer, defining model and serialized fields."""

        model = CertificateModel
        fields: ClassVar[list[str]] = ['id', 'common_name']
        read_only_fields: ClassVar[list[str]] = ['id']
