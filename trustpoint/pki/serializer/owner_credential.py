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

from onboarding.enums import NoOnboardingPkiProtocol, OnboardingPkiProtocol, OnboardingProtocol
from onboarding.models import NoOnboardingConfigModel, OnboardingConfigModel
from pki.models import OwnerCredentialModel, RemoteIssuedCredentialModel
from pki.models.cert_profile import CertificateProfileModel
from util.field import UniqueNameValidator

_KEY_TYPE_CHOICES = [
    'RSA-2048',
    'RSA-3072',
    'RSA-4096',
    'ECC-SECP256R1',
    'ECC-SECP384R1',
    'ECC-SECP521R1',
]

class OwnerCredentialSerializer(serializers.ModelSerializer[OwnerCredentialModel]):
    """Read-only serializer for OwnerCredentialModel instances."""

    owner_credential_type_display = serializers.CharField(
        source='get_owner_credential_type_display',
        read_only=True,
    )
    has_valid_domain_credential = serializers.BooleanField(read_only=True)
    truststore_id = serializers.SerializerMethodField()

    class Meta:
        """Metadata for OwnerCredentialSerializer."""

        model = OwnerCredentialModel
        fields: ClassVar[list[str]] = [
            'id',
            'unique_name',
            'owner_credential_type',
            'owner_credential_type_display',
            'remote_host',
            'remote_port',
            'remote_path',
            'remote_path_domain_credential',
            'est_username',
            'key_type',
            'has_valid_domain_credential',
            'truststore_id',
            'created_at',
        ]
        read_only_fields: ClassVar[list[str]] = fields

    def get_truststore_id(self, obj: OwnerCredentialModel) -> int | None:
        """Return the associated TLS truststore id, if any."""
        if obj.no_onboarding_config and obj.no_onboarding_config.trust_store_id:
            return obj.no_onboarding_config.trust_store_id
        if obj.onboarding_config and obj.onboarding_config.trust_store_id:
            return obj.onboarding_config.trust_store_id
        return None

class OwnerCredentialFileImportSerializer(serializers.Serializer[Any]):
    """Serializer for creating an OwnerCredential via file import (PEM files)."""

    unique_name = serializers.CharField(
        max_length=100,
        required=False,
        allow_blank=True,
        validators=[UniqueNameValidator()],
        help_text='Optional unique name for the DevOwnerID.',
    )
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
        """Parse and return the private key serializer from uploaded file."""
        pk_file = attrs.get('private_key_file')
        if pk_file is None:
            raise serializers.ValidationError({'private_key_file': 'No private key file provided.'})
        pw = attrs.get('private_key_file_password') or None
        try:
            return PrivateKeySerializer.from_bytes(pk_file.read(), pw)
        except Exception as exc:
            msg = 'Failed to parse the private key file. Wrong password or corrupted.'
            raise serializers.ValidationError({'private_key_file': msg}) from exc

    def _parse_certificate(self, attrs: dict[str, Any]) -> CertificateSerializer:
        """Parse and return the certificate serializer from uploaded file."""
        cert_file = attrs.get('certificate')
        if cert_file is None:
            raise serializers.ValidationError({'certificate': 'No certificate file provided.'})
        try:
            return CertificateSerializer.from_bytes(cert_file.read())
        except Exception as exc:
            msg = 'Failed to parse the certificate. Seems to be corrupted.'
            raise serializers.ValidationError({'certificate': msg}) from exc

    def _check_duplicate_certificate(self, certificate_serializer: CertificateSerializer) -> None:
        """Raise a ValidationError if the certificate is already used by another DevOwnerID."""
        from cryptography.hazmat.primitives import hashes  # noqa: PLC0415

        from pki.models.certificate import CertificateModel  # noqa: PLC0415

        fingerprint = certificate_serializer.as_crypto().fingerprint(hashes.SHA256()).hex()
        cert_in_db = CertificateModel.get_cert_by_sha256_fingerprint(fingerprint)
        if not cert_in_db:
            return
        dup_qs = OwnerCredentialModel.objects.filter(
            remote_issued_credentials__credential__certificate=cert_in_db,
            remote_issued_credentials__issued_credential_type=(
                RemoteIssuedCredentialModel.RemoteIssuedCredentialType.DEV_OWNER_ID
            ),
        )
        existing = dup_qs.first()
        if existing is not None:
            msg = f'DevOwnerID "{existing.unique_name}" already uses this certificate.'
            raise serializers.ValidationError({'certificate': msg})

    def _parse_chain(self, attrs: dict[str, Any]) -> CertificateCollectionSerializer | None:
        """Parse and return the optional certificate chain serializer."""
        chain_file = attrs.get('certificate_chain')
        if not chain_file:
            return None
        try:
            return CertificateCollectionSerializer.from_bytes(chain_file.read())
        except Exception as exc:
            msg = 'Failed to parse the certificate chain.'
            raise serializers.ValidationError({'certificate_chain': msg}) from exc

    def _resolve_unique_name(
        self, attrs: dict[str, Any], certificate_serializer: CertificateSerializer
    ) -> str:
        """Derive and validate the unique name for the new DevOwnerID."""
        unique_name: str = attrs.get('unique_name', '')
        if not unique_name:
            from util.field import get_certificate_name  # noqa: PLC0415
            unique_name = get_certificate_name(certificate_serializer.as_crypto()) or ''
        if not unique_name:
            raise serializers.ValidationError(
                {'unique_name': 'Could not derive a unique name from the certificate.'}
            )
        if OwnerCredentialModel.objects.filter(unique_name=unique_name).exists():
            msg = f'An owner credential with name "{unique_name}" already exists.'
            raise serializers.ValidationError({'unique_name': msg})
        return unique_name

    def validate(self, attrs: dict[str, Any]) -> dict[str, Any]:
        """Parse uploaded files and build a CredentialSerializer."""
        private_key_serializer = self._parse_private_key(attrs)
        certificate_serializer = self._parse_certificate(attrs)
        self._check_duplicate_certificate(certificate_serializer)
        chain_serializer = self._parse_chain(attrs)
        unique_name = self._resolve_unique_name(attrs, certificate_serializer)

        attrs['_unique_name'] = unique_name
        attrs['_credential_serializer'] = CredentialSerializer.from_serializers(
            private_key_serializer=private_key_serializer,
            certificate_serializer=certificate_serializer,
            certificate_collection_serializer=chain_serializer,
        )
        return attrs

    def create(self, validated_data: dict[str, Any]) -> OwnerCredentialModel:
        """Persist the DevOwnerID from file import."""
        try:
            return OwnerCredentialModel.create_new_owner_credential(
                unique_name=validated_data['_unique_name'],
                credential_serializer=validated_data['_credential_serializer'],
            )
        except DjangoValidationError as exc:
            errors = exc.message_dict if hasattr(exc, 'message_dict') else exc.messages
            raise serializers.ValidationError(errors) from exc

class OwnerCredentialEstBasicAuthSerializer(serializers.Serializer[Any]):
    """Serializer for creating an OwnerCredential via EST with Basic Auth (username/password)."""

    unique_name = serializers.CharField(
        max_length=100,
        required=False,
        allow_blank=True,
        validators=[UniqueNameValidator()],
        help_text='Optional unique name.',
    )
    remote_host = serializers.CharField(
        max_length=253,
        help_text='Hostname or IP of the remote EST server.',
    )
    remote_port = serializers.IntegerField(
        default=443,
        min_value=1,
        max_value=65535,
        help_text='Port of the remote EST server.',
    )
    remote_path = serializers.CharField(
        max_length=255,
        default='/.well-known/est/simpleenroll',
        help_text='EST enrollment path.',
    )
    est_username = serializers.CharField(
        max_length=128,
        help_text='EST Basic Auth username.',
    )
    est_password = serializers.CharField(
        max_length=128,
        write_only=True,
        help_text='EST Basic Auth password.',
    )
    key_type = serializers.ChoiceField(
        choices=_KEY_TYPE_CHOICES,
        default='ECC-SECP256R1',
        help_text='Key type for the generated key pair.',
    )
    truststore_id = serializers.IntegerField(
        required=False,
        allow_null=True,
        help_text='Optional ID of a TLS truststore to verify the EST server certificate.',
    )

    def validate_unique_name(self, value: str) -> str:
        """Validate that the unique name is not already in use."""
        if value and OwnerCredentialModel.objects.filter(unique_name=value).exists():
            msg = f'An owner credential with name "{value}" already exists.'
            raise serializers.ValidationError(msg)
        return value

    def validate_truststore_id(self, value: int | None) -> int | None:
        """Validate that the truststore exists if provided."""
        if value is not None:
            from pki.models.truststore import TruststoreModel  # noqa: PLC0415
            if not TruststoreModel.objects.filter(pk=value).exists():
                msg = f'Truststore with id {value} does not exist.'
                raise serializers.ValidationError(msg)
        return value

    def validate(self, attrs: dict[str, Any]) -> dict[str, Any]:
        """Derive unique_name if not provided."""
        unique_name = attrs.get('unique_name') or ''
        if not unique_name:
            host = attrs['remote_host']
            candidate = host
            counter = 1
            while OwnerCredentialModel.objects.filter(unique_name=candidate).exists():
                candidate = f'{host}-{counter}'
                counter += 1
            unique_name = candidate
        attrs['_unique_name'] = unique_name
        return attrs

    def create(self, validated_data: dict[str, Any]) -> OwnerCredentialModel:
        """Create an OwnerCredentialModel with EST Basic Auth config."""
        from pki.models.truststore import TruststoreModel  # noqa: PLC0415

        no_onboarding_config = NoOnboardingConfigModel(
            pki_protocols=NoOnboardingPkiProtocol.EST_USERNAME_PASSWORD,
            est_password=validated_data['est_password'],
        )
        truststore_id = validated_data.get('truststore_id')
        if truststore_id:
            no_onboarding_config.trust_store = TruststoreModel.objects.get(pk=truststore_id)
        no_onboarding_config.save()

        return OwnerCredentialModel.objects.create(
            unique_name=validated_data['_unique_name'],
            no_onboarding_config=no_onboarding_config,
            remote_host=validated_data['remote_host'],
            remote_port=validated_data['remote_port'],
            remote_path=validated_data['remote_path'],
            est_username=validated_data['est_username'],
            key_type=validated_data.get('key_type', 'ECC-SECP256R1'),
            owner_credential_type=OwnerCredentialModel.OwnerCredentialTypeChoice.REMOTE_EST,
        )

class OwnerCredentialEstMtlsSerializer(serializers.Serializer[Any]):
    """Serializer for creating an OwnerCredential via EST with IDevID-based mTLS onboarding."""

    unique_name = serializers.CharField(
        max_length=100,
        required=False,
        allow_blank=True,
        validators=[UniqueNameValidator()],
        help_text='Optional unique name.',
    )
    remote_host = serializers.CharField(
        max_length=253,
        help_text='Hostname or IP of the remote EST server.',
    )
    remote_port = serializers.IntegerField(
        default=443,
        min_value=1,
        max_value=65535,
        help_text='Port of the remote EST server.',
    )
    remote_path = serializers.CharField(
        max_length=255,
        default='/.well-known/est/simpleenroll',
        help_text='EST enrollment path for DevOwnerID.',
    )
    remote_path_domain_credential = serializers.CharField(
        max_length=255,
        default='/.well-known/est/simpleenroll',
        help_text='EST enrollment path for Domain Credential.',
    )
    est_username = serializers.CharField(
        max_length=128,
        help_text='EST username.',
    )
    est_password = serializers.CharField(
        max_length=128,
        write_only=True,
        help_text='EST password.',
    )
    key_type = serializers.ChoiceField(
        choices=_KEY_TYPE_CHOICES,
        default='ECC-SECP256R1',
        help_text='Key type for the generated key pair.',
    )
    truststore_id = serializers.IntegerField(
        required=False,
        allow_null=True,
        help_text='Optional ID of a TLS truststore to verify the EST server certificate.',
    )

    def validate_unique_name(self, value: str) -> str:
        """Validate that the unique name is not already in use."""
        if value and OwnerCredentialModel.objects.filter(unique_name=value).exists():
            msg = f'An owner credential with name "{value}" already exists.'
            raise serializers.ValidationError(msg)
        return value

    def validate_truststore_id(self, value: int | None) -> int | None:
        """Validate that the truststore exists if provided."""
        if value is not None:
            from pki.models.truststore import TruststoreModel  # noqa: PLC0415
            if not TruststoreModel.objects.filter(pk=value).exists():
                msg = f'Truststore with id {value} does not exist.'
                raise serializers.ValidationError(msg)
        return value

    def validate(self, attrs: dict[str, Any]) -> dict[str, Any]:
        """Derive unique_name if not provided."""
        unique_name = attrs.get('unique_name') or ''
        if not unique_name:
            host = attrs['remote_host']
            candidate = host
            counter = 1
            while OwnerCredentialModel.objects.filter(unique_name=candidate).exists():
                candidate = f'{host}-{counter}'
                counter += 1
            unique_name = candidate
        attrs['_unique_name'] = unique_name
        return attrs

    def create(self, validated_data: dict[str, Any]) -> OwnerCredentialModel:
        """Create an OwnerCredentialModel with EST onboarding config."""
        from pki.models.truststore import TruststoreModel  # noqa: PLC0415

        onboarding_config = OnboardingConfigModel(
            pki_protocols=OnboardingPkiProtocol.EST,
            onboarding_protocol=OnboardingProtocol.EST_USERNAME_PASSWORD,
            est_password=validated_data['est_password'],
        )
        truststore_id = validated_data.get('truststore_id')
        if truststore_id:
            onboarding_config.trust_store = TruststoreModel.objects.get(pk=truststore_id)
        onboarding_config.save()

        return OwnerCredentialModel.objects.create(
            unique_name=validated_data['_unique_name'],
            onboarding_config=onboarding_config,
            remote_host=validated_data['remote_host'],
            remote_port=validated_data['remote_port'],
            remote_path=validated_data['remote_path'],
            remote_path_domain_credential=validated_data.get(
                'remote_path_domain_credential', '/.well-known/est/simpleenroll'
            ),
            est_username=validated_data['est_username'],
            key_type=validated_data.get('key_type', 'ECC-SECP256R1'),
            owner_credential_type=OwnerCredentialModel.OwnerCredentialTypeChoice.REMOTE_EST_ONBOARDING,
        )

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

    dns_names = serializers.CharField(
        required=False, allow_blank=True, help_text='Comma-separated DNS names.'
    )
    ip_addresses = serializers.CharField(
        required=False, allow_blank=True, help_text='Comma-separated IP addresses.'
    )
    rfc822_names = serializers.CharField(
        required=False, allow_blank=True, help_text='Comma-separated RFC 822 email addresses.'
    )
    uris = serializers.CharField(
        required=False, allow_blank=True, help_text='Comma-separated URIs.'
    )

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
