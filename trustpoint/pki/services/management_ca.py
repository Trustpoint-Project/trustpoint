# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Lifecycle operations for the CA hierarchy used for management certificates."""

from __future__ import annotations

from typing import Any, cast

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import NameOID
from django.core.exceptions import ValidationError
from django.db import transaction
from django.utils.translation import gettext_lazy as _

from crypto.application.private_keys import ManagedMLDSAPrivateKey, generate_managed_signing_private_key
from crypto.models import CryptoManagedKeyModel
from management.models import SecurityConfig
from pki.management.commands.create_management_ca import ISSUING_CA_NAME
from pki.models import CaModel, CertificateProfileModel
from pki.services.key_generation import key_spec_for_key_type, supported_key_type_choices
from pki.util.cert_req_converter import JSONCertRequestConverter
from pki.util.x509 import (
    CertificateGenerator,
    _unwrap_mldsa_managed_key,
    validate_certificate_signing_private_key,
)

SELF_SIGNED_MANAGEMENT_CA_PROFILE = 'issuing_ca'
SELF_SIGNED_MANAGEMENT_CA_OU = 'Self-Signed Management CA'


SELF_SIGNED_CA_PREFIX = 'SelfSignedCA_'
MAX_COMMON_NAME_BYTES = 64


def self_signed_ca_name(unique_name: str) -> str:
    """Apply the mandatory prefix once and validate the final name."""
    if not unique_name.startswith(SELF_SIGNED_CA_PREFIX):
        unique_name = f'{SELF_SIGNED_CA_PREFIX}{unique_name}'
    if unique_name == SELF_SIGNED_CA_PREFIX:
        raise ValidationError(_('Enter a unique name after the SelfSignedCA_ prefix.'))
    if len(unique_name.encode('utf-8')) > MAX_COMMON_NAME_BYTES:
        raise ValidationError(_('The full CA name, including SelfSignedCA_, must not exceed 64 UTF-8 bytes.'))
    return unique_name


class ManagementCAService:
    """Select and validate the management CA used by Trustpoint."""

    @staticmethod
    def get_issuing_ca(*, lock: bool = False) -> CaModel | None:
        """Return the management CA selected for user authentication.

        The enabled ``CertificateAuthenticationConfig`` wins, so externally
        configured management CAs work without the generated hierarchy. The
        built-in Management Issuing CA remains the fallback for existing setups.
        """
        from management.models import CertificateAuthenticationConfig  # noqa: PLC0415

        queryset = CaModel.objects.filter(ca_role=CaModel.CaRole.MANAGEMENT, is_active=True)
        if lock:
            queryset = queryset.select_for_update()
        configs = CertificateAuthenticationConfig.objects.select_related('issuing_ca').filter(
            issuing_ca__ca_role=CaModel.CaRole.MANAGEMENT,
            issuing_ca__is_active=True,
            issuing_ca__credential__isnull=False,
        )
        config = configs.filter(enabled=True).first() or configs.order_by('-pk').first()
        if config is not None:
            if lock:
                return queryset.filter(pk=config.issuing_ca_id).first()
            return config.issuing_ca
        return queryset.filter(unique_name=ISSUING_CA_NAME).first()

    @staticmethod
    def get_available_issuing_cas() -> list[CaModel]:
        """Return management CAs that hold a certificate and can sign locally."""
        return list(
            CaModel.objects.filter(
                ca_role=CaModel.CaRole.MANAGEMENT,
                is_active=True,
                credential__isnull=False,
                credential__certificate__isnull=False,
            )
            .select_related('credential__certificate')
            .order_by('unique_name')
        )

    @classmethod
    @transaction.atomic
    def select_issuing_ca(cls, ca_id: int) -> CaModel:
        """Select a management CA for certificate authentication and disable other selections."""
        from management.models import CertificateAuthenticationConfig  # noqa: PLC0415

        ca = CaModel.objects.select_for_update().filter(pk=ca_id).first()
        if ca is None or not ca.is_management_ca or not ca.is_active:
            raise ValidationError(_('Select an active management CA.'))
        if ca.ca_certificate_model is None or ca.credential is None:
            raise ValidationError(_('The selected management CA has no usable certificate.'))
        CertificateAuthenticationConfig.objects.exclude(issuing_ca=ca).delete()
        CertificateAuthenticationConfig.objects.get_or_create(issuing_ca=ca)
        return ca


@transaction.atomic
def create_self_signed_ca(*, unique_name: str, key_type: str, ca_role: int = CaModel.CaRole.ISSUING) -> CaModel:
    """Create a self-signed CA using the default ``issuing_ca`` certificate profile."""
    config = SecurityConfig.objects.select_for_update().first()
    if config is None or not config.auto_gen_pki:
        raise ValidationError(_('Auto-generated PKI creation is disabled in the Security Settings.'))
    if ca_role == CaModel.CaRole.MANAGEMENT and not config.allow_self_signed_ca_creation:
        raise ValidationError(_('Self-signed management CA creation is disabled in the Security Settings.'))
    if ca_role not in CaModel.CaRole.values:
        raise ValidationError(_('Select a valid CA role.'))
    unique_name = self_signed_ca_name(unique_name)
    subject_ou = SELF_SIGNED_MANAGEMENT_CA_OU if ca_role == CaModel.CaRole.MANAGEMENT else 'Self-Signed Issuing CA'
    if CaModel.objects.filter(unique_name=unique_name).exists():
        raise ValidationError(_('A CA with this unique name already exists.'))
    if CryptoManagedKeyModel.objects.filter(alias=unique_name).exists():
        raise ValidationError(_('A cryptographic key with this name already exists.'))
    if key_type not in {value for value, _label in supported_key_type_choices()}:
        raise ValidationError(_('The active crypto backend does not support this key type.'))
    try:
        profile = CertificateProfileModel.objects.get(unique_name=SELF_SIGNED_MANAGEMENT_CA_PROFILE)
    except CertificateProfileModel.DoesNotExist as exc:
        raise ValidationError(_('The issuing_ca certificate profile is not available.')) from exc

    profile_data = profile.profile
    private_key = generate_managed_signing_private_key(
        alias=unique_name,
        key_spec=key_spec_for_key_type(key_type),
    )
    public_key = cast('Any', private_key.public_key())
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, unique_name),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, subject_ou),
        ]
    )
    builder = JSONCertRequestConverter.from_json(
        {
            'type': 'cert_request',
            'subject': {
                'common_name': unique_name,
                'organizational_unit_name': subject_ou,
            },
            'extensions': profile_data.get('ext', {}),
            'validity': profile_data.get('validity', {}),
        }
    )
    builder = (
        builder.issuer_name(subject)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(public_key), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(public_key), critical=False)
    )

    actual_key = validate_certificate_signing_private_key(_unwrap_mldsa_managed_key(private_key))
    if isinstance(private_key, ManagedMLDSAPrivateKey):
        certificate = builder.sign(private_key=actual_key, algorithm=None)
    else:
        certificate = builder.sign(private_key=actual_key, algorithm=hashes.SHA256())

    return CertificateGenerator.save_issuing_ca(
        issuing_ca_cert=certificate,
        private_key=private_key,  # type: ignore[arg-type]
        chain=[],
        unique_name=unique_name,
        ca_type=CaModel.CaTypeChoice.SELF_SIGNED,
        ca_role=ca_role,
    )


def create_self_signed_management_ca(*, unique_name: str, key_type: str) -> CaModel:
    """Create a self-signed CA with the management role."""
    return create_self_signed_ca(unique_name=unique_name, key_type=key_type, ca_role=CaModel.CaRole.MANAGEMENT)
