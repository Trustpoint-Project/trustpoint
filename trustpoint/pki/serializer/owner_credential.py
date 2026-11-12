# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Serializers for Owner Credential (DevOwnerID) API endpoints."""

from __future__ import annotations

from typing import Any, ClassVar

from django.core.exceptions import ValidationError as DjangoValidationError
from rest_framework import serializers
from trustpoint_core.serializer import (
    CertificateCollectionSerializer,
    CertificateSerializer,
    CredentialSerializer,
    PrivateKeySerializer,
)

from pki.models import RemoteIssuedCredentialModel
from pki.models.cert_profile import CertificateProfileModel
from pki.services import credential_upload as uploads
from pki.util.san import SAN_FIELDS, SanValidationError, normalize_san_values


class OwnerCredentialSerializer(serializers.ModelSerializer[RemoteIssuedCredentialModel]):
    """Read-only serializer for DevOwnerID credential rows."""

    devownerid_certificate_pem = serializers.SerializerMethodField()

    class Meta:
        """Metadata for OwnerCredentialSerializer."""

        model = RemoteIssuedCredentialModel
        fields: ClassVar[list[str]] = [
            'id',
            'common_name',
            'ca',
            'devownerid_certificate_pem',
            'created_at',
        ]
        read_only_fields: ClassVar[list[str]] = fields

    def get_devownerid_certificate_pem(self, obj: RemoteIssuedCredentialModel) -> str | None:
        """Return the PEM-encoded DevOwnerID certificate, or None if not yet issued."""
        cert = obj.credential.certificate
        if cert is None:
            return None
        return cert.cert_pem


class OwnerCredentialFileImportSerializer(serializers.Serializer[Any]):
    """Serializer for creating a DevOwnerID via file import (PEM files)."""

    certificate = serializers.FileField(
        help_text='DevOwnerID certificate file (.pem / .cer / .der / .p7b / .p7c).',
    )
    certificate_chain = serializers.FileField(
        required=False,
        help_text='Optional certificate chain (.pem / .p7b / .p7c).',
    )
    private_key_file = serializers.FileField(
        help_text='Private key file (.pem / .key).',
    )
    private_key_file_password = serializers.CharField(
        required=False,
        allow_blank=True,
        write_only=True,
        help_text='Optional password for the private key.',
    )

    def _parse_private_key(self, attrs: dict[str, Any]) -> PrivateKeySerializer:
        """Parse bounded private-key input and retain DRF field-level errors."""
        try:
            data = uploads.read_credential_upload(
                attrs.get('private_key_file'),
                kind=uploads.CredentialFileKind.PRIVATE_KEY,
            )
            password = uploads.encode_upload_password(attrs.get('private_key_file_password'))
            return uploads.parse_private_key(data, password)
        except uploads.CredentialUploadError as exc:
            messages = {
                uploads.CredentialUploadErrorCode.MISSING: 'No private key file provided.',
                uploads.CredentialUploadErrorCode.TOO_LARGE: 'Private key file is too large, max. 64 kiB.',
                uploads.CredentialUploadErrorCode.INVALID_PASSWORD: (
                    'The private key password contains invalid data that cannot be encoded in UTF-8.'
                ),
            }
            msg = messages.get(exc.code, 'Failed to parse the private key file. Wrong password or corrupted.')
            raise serializers.ValidationError({'private_key_file': msg}) from exc

    def _parse_certificate(self, attrs: dict[str, Any]) -> CertificateSerializer:
        """Parse a bounded certificate and retain DRF field-level errors."""
        try:
            data = uploads.read_credential_upload(attrs.get('certificate'), kind=uploads.CredentialFileKind.CERTIFICATE)
            return uploads.parse_certificate(data)
        except uploads.CredentialUploadError as exc:
            messages = {
                uploads.CredentialUploadErrorCode.MISSING: 'No certificate file provided.',
                uploads.CredentialUploadErrorCode.TOO_LARGE: 'Certificate file is too large, max. 64 kiB.',
            }
            msg = messages.get(exc.code, 'Failed to parse the certificate. Seems to be corrupted.')
            raise serializers.ValidationError({'certificate': msg}) from exc

    def _check_duplicate_certificate(self, certificate_serializer: CertificateSerializer) -> None:
        """Raise a ValidationError if the certificate is already used by another DevOwnerID."""
        from cryptography.hazmat.primitives import hashes  # noqa: PLC0415

        from pki.models.certificate import CertificateModel  # noqa: PLC0415

        fingerprint = certificate_serializer.as_crypto().fingerprint(hashes.SHA256()).hex()
        cert_in_db = CertificateModel.get_cert_by_sha256_fingerprint(fingerprint)
        if not cert_in_db:
            return
        existing = RemoteIssuedCredentialModel.objects.filter(
            credential__certificate=cert_in_db,
            issued_credential_type=RemoteIssuedCredentialModel.RemoteIssuedCredentialType.DEV_OWNER_ID,
        ).first()
        if existing is not None:
            msg = f'DevOwnerID "{existing.common_name}" already uses this certificate.'
            raise serializers.ValidationError({'certificate': msg})

    def _parse_chain(self, attrs: dict[str, Any]) -> CertificateCollectionSerializer | None:
        """Parse an optional bounded chain and retain DRF field-level errors."""
        upload = attrs.get('certificate_chain')
        if not upload:
            return None
        try:
            data = uploads.read_credential_upload(upload, kind=uploads.CredentialFileKind.CHAIN)
            return uploads.parse_certificate_chain(data)
        except uploads.CredentialUploadError as exc:
            msg = (
                'Certificate chain file is too large, max. 256 kiB.'
                if (exc.code == uploads.CredentialUploadErrorCode.TOO_LARGE)
                else 'Failed to parse the certificate chain.'
            )
            raise serializers.ValidationError({'certificate_chain': msg}) from exc

    def _resolve_common_name(self, certificate_serializer: CertificateSerializer) -> str:
        """Derive the DevOwnerID display name from the certificate."""
        from util.field import get_certificate_name  # noqa: PLC0415

        common_name = get_certificate_name(certificate_serializer.as_crypto()) or ''
        if not common_name:
            raise serializers.ValidationError({'certificate': 'Could not derive a common name from the certificate.'})
        return common_name

    def validate(self, attrs: dict[str, Any]) -> dict[str, Any]:
        """Parse uploaded files and build a CredentialSerializer."""
        private_key_serializer = self._parse_private_key(attrs)
        certificate_serializer = self._parse_certificate(attrs)
        self._check_duplicate_certificate(certificate_serializer)
        chain_serializer = self._parse_chain(attrs)
        common_name = self._resolve_common_name(certificate_serializer)

        attrs['_common_name'] = common_name
        attrs['_credential_serializer'] = CredentialSerializer.from_serializers(
            private_key_serializer=private_key_serializer,
            certificate_serializer=certificate_serializer,
            certificate_collection_serializer=chain_serializer,
        )
        return attrs

    def create(self, validated_data: dict[str, Any]) -> RemoteIssuedCredentialModel:
        """Persist the DevOwnerID from file import."""
        try:
            return RemoteIssuedCredentialModel.create_imported_dev_owner_id(
                common_name=validated_data['_common_name'],
                credential_serializer=validated_data['_credential_serializer'],
            )
        except DjangoValidationError as exc:
            errors = exc.message_dict if hasattr(exc, 'message_dict') else exc.messages
            raise serializers.ValidationError(errors) from exc


class CertificateIssuanceContentSerializer(serializers.Serializer[Any]):
    """Serializer for the certificate subject / SAN / validity fields used in cert request actions."""

    cert_profile_pk = serializers.IntegerField(
        required=False,
        allow_null=True,
        help_text='PK of the certificate profile to use. Defaults to the profile matching the action.',
    )

    common_name = serializers.CharField(required=False, allow_blank=True)
    organization_name = serializers.CharField(required=False, allow_blank=True)
    organizational_unit_name = serializers.CharField(required=False, allow_blank=True)
    country_name = serializers.CharField(required=False, allow_blank=True, max_length=2)
    state_or_province_name = serializers.CharField(required=False, allow_blank=True)
    locality_name = serializers.CharField(required=False, allow_blank=True)
    email_address = serializers.CharField(required=False, allow_blank=True)

    dns_names = serializers.CharField(required=False, allow_blank=True, help_text='Comma-separated DNS names.')
    ip_addresses = serializers.CharField(required=False, allow_blank=True, help_text='Comma-separated IP addresses.')
    rfc822_names = serializers.CharField(
        required=False, allow_blank=True, help_text='Comma-separated RFC 822 email addresses.'
    )
    uris = serializers.CharField(required=False, allow_blank=True, help_text='Comma-separated URIs.')

    days = serializers.IntegerField(required=False, allow_null=True, min_value=0)
    hours = serializers.IntegerField(required=False, allow_null=True, min_value=0)
    minutes = serializers.IntegerField(required=False, allow_null=True, min_value=0)
    seconds = serializers.IntegerField(required=False, allow_null=True, min_value=0)

    def validate_cert_profile_pk(self, value: int | None) -> int | None:
        """Validate that the profile exists if provided."""
        if value is not None and not CertificateProfileModel.objects.filter(pk=value).exists():
            msg = f'Certificate profile with pk {value} does not exist.'
            raise serializers.ValidationError(msg)
        return value

    def validate(self, attrs: dict[str, Any]) -> dict[str, Any]:
        """Normalize editable SAN content and return field-level errors for malformed identities."""
        errors = {}
        for field in SAN_FIELDS:
            if field not in attrs:
                continue
            try:
                attrs[field] = ', '.join(normalize_san_values(field, attrs[field]))
            except SanValidationError as exc:
                errors[field] = str(exc)
        if errors:
            raise serializers.ValidationError(errors)
        return attrs
