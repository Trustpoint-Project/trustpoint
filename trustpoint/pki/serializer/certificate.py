# Copyright (c) 2024 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Serializers for Certificate-related API endpoints.

Defines classes that handle validation and transformation
of Certificate model instances to and from JSON.
"""

from typing import Any, ClassVar

from cryptography import x509
from drf_spectacular.utils import extend_schema_field
from rest_framework import serializers
from trustpoint_core.archiver import ArchiveFormat
from trustpoint_core.oid import NameOid
from trustpoint_core.serializer import CertificateFormat

from pki.models.certificate import CertificateModel, RevokedCertificateModel
from pki.models.issued_credential import IssuedCredentialModel
from pki.services.certificate_download import certificate_chain

OID_NAMES = {oid.dotted_string: oid.verbose_name for oid in NameOid}


class CertificateSerializer(serializers.ModelSerializer[CertificateModel]):
    """Serializer for Certificate instances.

    Handles conversion between Certificate model objects and JSON representations.
    """

    class Meta:
        """Metadata for CertificateSerializer, defining model and serialized fields."""

        model = CertificateModel
        fields: ClassVar[list[str]] = ['id', 'common_name']
        read_only_fields: ClassVar[list[str]] = ['id']


class CertificateSummarySerializer(CertificateSerializer):
    """Read-only certificate inventory information, independent of credential/private-key records."""

    certificate_status = serializers.ChoiceField(choices=CertificateModel.CertificateStatus.choices, read_only=True)
    status_display = serializers.CharField(source='table_status', read_only=True)
    is_ca = serializers.BooleanField(read_only=True)
    issuer_certificate = serializers.IntegerField(source='issuer_id_id', read_only=True, allow_null=True)

    class Meta(CertificateSerializer.Meta):
        """Keep the original identity fields and add useful inventory metadata."""

        fields: ClassVar[list[str]] = [
            'id',
            'common_name',
            'serial_number',
            'sha256_fingerprint',
            'not_valid_before',
            'not_valid_after',
            'certificate_status',
            'status_display',
            'is_ca',
            'is_self_signed',
            'issuer_certificate',
            'spki_algorithm',
            'spki_key_size',
            'created_at',
        ]
        read_only_fields = fields


class CertificateRevocationSerializer(serializers.ModelSerializer[RevokedCertificateModel]):
    """Persisted revocation details, when the certificate has been revoked."""

    class Meta:
        """Return the date, reason, and associated CA without exposing credentials."""

        model = RevokedCertificateModel
        fields = ('revoked_at', 'revocation_reason', 'ca')
        read_only_fields = fields


class CertificateIssuedCredentialSerializer(serializers.ModelSerializer[IssuedCredentialModel]):
    """Public device and profile associations shown alongside a certificate in the UI."""

    device_name = serializers.CharField(source='device.common_name', read_only=True)
    onboarding_protocol = serializers.CharField(source='device.get_onboarding_protocol_display', read_only=True)
    credential_type_display = serializers.CharField(source='get_issued_credential_type_display', read_only=True)

    class Meta:
        """Identifiers and issuance metadata, without credential contents or secrets."""

        model = IssuedCredentialModel
        fields = (
            'id',
            'credential',
            'device',
            'device_name',
            'domain',
            'onboarding_protocol',
            'issued_credential_type',
            'credential_type_display',
            'issued_using_cert_profile',
        )
        read_only_fields = fields


def name_attributes(name: x509.Name) -> list[dict[str, Any]]:
    """Preserve repeated attributes and relative distinguished name groupings."""
    return [
        {
            'rdn': index,
            'oid': attribute.oid.dotted_string,
            'name': OID_NAMES.get(attribute.oid.dotted_string, attribute.oid.dotted_string),
            'value': attribute.value.hex().upper() if isinstance(attribute.value, bytes) else attribute.value,
        }
        for index, rdn in enumerate(name.rdns)
        for attribute in rdn
    ]


def general_names(
    names: x509.GeneralNames | x509.SubjectAlternativeName | x509.IssuerAlternativeName,
) -> list[dict[str, Any]]:
    """Represent all GeneralName types, including directory names and opaque other names."""
    result = []
    for name in names:
        if isinstance(name, x509.DirectoryName):
            value: Any = name_attributes(name.value)
        elif isinstance(name, x509.RegisteredID):
            value = name.value.dotted_string
        elif isinstance(name, x509.OtherName):
            value = {'oid': name.type_id.dotted_string, 'der_hex': name.value.hex().upper()}
        else:
            value = str(name.value)
        result.append({'type': type(name).__name__, 'value': value})
    return result


def extension_value(value: x509.ExtensionType) -> Any:  # noqa: PLR0911
    """Expose common extensions as JSON, with a readable fallback for other extensions."""
    if isinstance(value, x509.BasicConstraints):
        return {'ca': value.ca, 'path_length': value.path_length}
    if isinstance(value, x509.KeyUsage):
        fields = (
            'digital_signature',
            'content_commitment',
            'key_encipherment',
            'data_encipherment',
            'key_agreement',
            'key_cert_sign',
            'crl_sign',
        )
        return {
            **{field: getattr(value, field) for field in fields},
            'encipher_only': value.encipher_only if value.key_agreement else None,
            'decipher_only': value.decipher_only if value.key_agreement else None,
        }
    if isinstance(value, x509.ExtendedKeyUsage):
        return [oid.dotted_string for oid in value]
    if isinstance(value, (x509.SubjectAlternativeName, x509.IssuerAlternativeName)):
        return general_names(value)
    if isinstance(value, x509.SubjectKeyIdentifier):
        return {'key_identifier': value.digest.hex().upper()}
    if isinstance(value, x509.AuthorityKeyIdentifier):
        return {
            'key_identifier': value.key_identifier.hex().upper() if value.key_identifier is not None else None,
            'authority_cert_issuer': general_names(x509.GeneralNames(value.authority_cert_issuer))
            if value.authority_cert_issuer is not None
            else None,
            'authority_cert_serial_number': f'{value.authority_cert_serial_number:X}'
            if value.authority_cert_serial_number is not None
            else None,
        }
    return str(value)


class CertificateDetailSerializer(CertificateSummarySerializer):
    """Full public X.509 details with structured names, extensions, and revocation information."""

    subject = serializers.SerializerMethodField()
    issuer = serializers.SerializerMethodField()
    extensions = serializers.SerializerMethodField()
    certificate_chain = serializers.SerializerMethodField()
    revocation = CertificateRevocationSerializer(source='revoked_certificate', read_only=True, allow_null=True)
    signature_algorithm = serializers.CharField(read_only=True)
    signature_algorithm_padding_scheme = serializers.CharField(read_only=True)
    days_left = serializers.IntegerField(read_only=True)
    is_root_ca = serializers.BooleanField(read_only=True)
    is_end_entity = serializers.BooleanField(read_only=True)
    issued_credentials = serializers.SerializerMethodField()
    issued_certificate_count = serializers.SerializerMethodField()

    class Meta(CertificateSummarySerializer.Meta):
        """Read-only certificate fields; write operations retain the existing serializer."""

        fields: ClassVar[list[str]] = [
            *CertificateSummarySerializer.Meta.fields,
            'version',
            'signature_algorithm_oid',
            'signature_algorithm',
            'signature_algorithm_padding_scheme',
            'signature_value',
            'spki_algorithm_oid',
            'spki_ec_curve_oid',
            'spki_ec_curve',
            'public_key_pem',
            'subject',
            'issuer',
            'extensions',
            'certificate_chain',
            'revocation',
            'days_left',
            'is_root_ca',
            'is_end_entity',
            'issued_credentials',
            'issued_certificate_count',
            'cert_pem',
        ]
        read_only_fields = fields

    def get_subject(self, obj: CertificateModel) -> list[dict[str, Any]]:
        """Return subject attributes in their original order and RDN groups."""
        return name_attributes(obj.get_certificate_serializer().as_crypto().subject)

    def get_issuer(self, obj: CertificateModel) -> list[dict[str, Any]]:
        """Return issuer distinguished-name attributes."""
        return name_attributes(obj.get_certificate_serializer().as_crypto().issuer)

    def get_extensions(self, obj: CertificateModel) -> list[dict[str, Any]]:
        """Include every extension, with its exact DER bytes for lossless interpretation."""
        return [
            {
                'oid': extension.oid.dotted_string,
                'critical': extension.critical,
                'value': extension_value(extension.value),
                'der_hex': extension.value.public_bytes().hex().upper(),
            }
            for extension in obj.get_certificate_serializer().as_crypto().extensions
        ]

    def get_certificate_chain(self, obj: CertificateModel) -> list[int]:
        """List known issuer certificate IDs from the direct issuer to the root."""
        try:
            return [issuer.pk for issuer in certificate_chain(obj)]
        except ValueError as exc:
            msg = 'Unable to build the certificate issuer chain.'
            raise serializers.ValidationError(msg) from exc

    @extend_schema_field(CertificateIssuedCredentialSerializer(many=True))
    def get_issued_credentials(self, obj: CertificateModel) -> list[dict[str, Any]]:
        """Expose local issuance associations used for device/profile navigation and revocation."""
        credentials = (
            IssuedCredentialModel.objects.filter(credential__certificate=obj)
            .select_related('device__onboarding_config', 'device__no_onboarding_config')
            .order_by('pk')
        )
        return [dict(item) for item in CertificateIssuedCredentialSerializer(credentials, many=True).data]

    def get_issued_certificate_count(self, obj: CertificateModel) -> int:
        """Count certificates linked to this issuer, excluding a self-reference."""
        return CertificateModel.objects.filter(issuer_id=obj).exclude(pk=obj.pk).count()


class CertificateDownloadSerializer(serializers.Serializer[Any]):
    """Options for a public certificate file download."""

    file_format = serializers.ChoiceField(choices=[item.value for item in CertificateFormat], default='pem')
    include_chain = serializers.BooleanField(default=False)


class CertificateArchiveSerializer(CertificateDownloadSerializer):
    """Select certificates and an archive format without changing their contents."""

    certificate_ids = serializers.ListField(
        child=serializers.IntegerField(min_value=1), allow_empty=False, max_length=1000
    )
    archive_format = serializers.ChoiceField(choices=[item.value for item in ArchiveFormat], default='zip')
