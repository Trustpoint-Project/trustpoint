# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Lifecycle and cryptographic operations for Traceability Credentials."""

from __future__ import annotations

import datetime
from contextlib import suppress
from dataclasses import dataclass, replace
from enum import StrEnum
from typing import TYPE_CHECKING, Any

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtensionOID, NameOID
from django.core.exceptions import ValidationError
from django.db import transaction

from crypto.application.private_keys import ManagedECPrivateKey, generate_managed_signing_private_key
from crypto.application.service import TrustpointCryptoBackend
from crypto.domain.algorithms import EllipticCurveName
from crypto.domain.errors import CryptoError
from crypto.domain.specs import EcKeySpec
from crypto.models import CryptoManagedKeyModel
from management.models.traceability import (
    TraceabilityCredentialGenerationModel,
    TraceabilityCredentialModel,
)
from pki.models.cert_profile import CertificateProfileModel
from pki.models.credential import CredentialModel

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence

type EvidenceDigest = hashes.SHA256 | hashes.SHA384


UNSUPPORTED_CURVE = 'Unsupported Traceability Credential curve.'
NAME_NOT_UNIQUE = 'Traceability Credential name must be unique.'
EC_KEY_REQUIRED = 'Traceability Credentials require an EC backend key.'
PURPOSE_NOT_ASSIGNED = 'Purpose is not assigned to this Traceability Credential.'
NOT_USABLE = 'Traceability Credential is not currently usable.'
INVALID_TYPE = 'Invalid Traceability Credential type.'
ALREADY_RETIRED = 'Traceability Credential is already retired.'
INVALID_PROFILE = 'The canonical Traceability Credential profile is missing or invalid.'
INVALID_BASIC_CONSTRAINTS = 'Traceability Credential profile must set CA=false.'
INVALID_KEY_USAGE = 'Traceability Credential profile must allow digitalSignature only.'


@dataclass(frozen=True, slots=True)
class TraceabilityCertificateData:
    """Validated certificate values supplied by a profile-driven form."""

    subject: x509.Name
    not_valid_before: datetime.datetime
    not_valid_after: datetime.datetime
    certificate_builder: x509.CertificateBuilder | None = None


@dataclass(frozen=True, slots=True)
class TraceabilitySigningResult:
    """Metadata returned after a successful traceability signature."""

    signature: bytes
    traceability_credential_id: int
    traceability_credential_name: str
    generation_id: int
    certificate_id: int
    certificate_fingerprint_sha256: str
    algorithm: str


class VerificationFailureReason(StrEnum):
    """Stable failure reasons for historical verification."""

    INVALID_SIGNATURE = 'INVALID_SIGNATURE'
    PURPOSE_MISMATCH = 'PURPOSE_MISMATCH'
    GENERATION_NOT_FOUND = 'GENERATION_NOT_FOUND'
    INVALID_CREDENTIAL_TYPE = 'INVALID_CREDENTIAL_TYPE'
    UNSUPPORTED_ALGORITHM = 'UNSUPPORTED_ALGORITHM'


@dataclass(frozen=True, slots=True)
class TraceabilityVerificationResult:
    """Structured result of historical Traceability Credential verification."""

    valid: bool
    traceability_credential_id: int
    traceability_credential_name: str
    generation_id: int
    certificate_id: int
    certificate_fingerprint_sha256: str
    algorithm: str
    failure_reason: VerificationFailureReason | None = None


class TraceabilityCredentialService:
    """Own all lifecycle mutations and cryptographic use of traceability credentials."""

    @staticmethod
    def _curve_values(
        curve: TraceabilityCredentialModel.Curve | str,
    ) -> tuple[EllipticCurveName, EvidenceDigest, str]:
        curve = TraceabilityCredentialModel.Curve(curve)
        if curve == TraceabilityCredentialModel.Curve.SECP256R1:
            return EllipticCurveName.SECP256R1, hashes.SHA256(), 'ECDSA-SHA256'
        if curve == TraceabilityCredentialModel.Curve.SECP384R1:
            return EllipticCurveName.SECP384R1, hashes.SHA384(), 'ECDSA-SHA384'
        raise ValidationError(UNSUPPORTED_CURVE)

    @staticmethod
    def _validate_canonical_profile() -> dict[str, object]:
        """Return the canonical profile after validating security-critical semantics."""
        profile = CertificateProfileModel.objects.filter(
            unique_name='traceability_credential',
            credential_type=CertificateProfileModel.ProfileCredentialType.EVIDENCE_SIGNING_CREDENTIAL,
        ).first()
        if profile is None:
            raise ValidationError(INVALID_PROFILE)
        profile_data = profile.profile
        TraceabilityCredentialService._validate_profile_security_semantics(profile_data)
        return profile_data

    @staticmethod
    def _validate_profile_security_semantics(profile_data: dict[str, Any]) -> None:
        """Validate profile-controlled certificate semantics required for traceability signing."""
        if (
            profile_data.get('credential_type')
            != CertificateProfileModel.ProfileCredentialType.EVIDENCE_SIGNING_CREDENTIAL
        ):
            raise ValidationError(INVALID_PROFILE)
        extensions = profile_data.get('ext', profile_data.get('extensions'))
        if not isinstance(extensions, dict):
            raise ValidationError(INVALID_PROFILE)
        TraceabilityCredentialService._validate_profile_basic_constraints(extensions.get('basic_constraints'))
        TraceabilityCredentialService._validate_profile_key_usage(extensions.get('key_usage'))
        if extensions.get('extended_key_usage') is not None:
            raise ValidationError(INVALID_PROFILE)

    @staticmethod
    def _validate_profile_basic_constraints(basic_constraints: object) -> None:
        """Validate that the profile requires an end-entity certificate."""
        if not isinstance(basic_constraints, dict) or basic_constraints.get('ca') is not False:
            raise ValidationError(INVALID_BASIC_CONSTRAINTS)

    @staticmethod
    def _validate_profile_key_usage(key_usage: object) -> None:
        """Validate that the profile permits only digital signatures."""
        if not isinstance(key_usage, dict) or key_usage.get('digital_signature') is not True:
            raise ValidationError(INVALID_KEY_USAGE)
        prohibited_fields = (
            'content_commitment',
            'key_encipherment',
            'data_encipherment',
            'key_agreement',
            'key_cert_sign',
            'crl_sign',
            'encipher_only',
            'decipher_only',
        )
        if any(key_usage.get(field) for field in prohibited_fields):
            raise ValidationError(INVALID_KEY_USAGE)

    @staticmethod
    def _apply_basic_constraints(
        builder: x509.CertificateBuilder,
        existing_extensions: Mapping[x509.ObjectIdentifier, object],
    ) -> x509.CertificateBuilder:
        """Validate or add the profile's CA=false BasicConstraints extension."""
        extension = existing_extensions.get(ExtensionOID.BASIC_CONSTRAINTS)
        if extension is None:
            return builder.add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        if not isinstance(extension, x509.BasicConstraints) or extension.ca:
            raise ValidationError(INVALID_BASIC_CONSTRAINTS)
        return builder

    @staticmethod
    def _apply_key_usage(
        builder: x509.CertificateBuilder,
        existing_extensions: Mapping[x509.ObjectIdentifier, object],
    ) -> x509.CertificateBuilder:
        """Validate or add the profile's digitalSignature-only KeyUsage extension."""
        extension = existing_extensions.get(ExtensionOID.KEY_USAGE)
        if extension is None:
            return builder.add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
        if not isinstance(extension, x509.KeyUsage) or not extension.digital_signature:
            raise ValidationError(INVALID_KEY_USAGE)
        prohibited_usage = (
            extension.content_commitment,
            extension.key_encipherment,
            extension.data_encipherment,
            extension.key_agreement,
            extension.key_cert_sign,
            extension.crl_sign,
        )
        if any(prohibited_usage) or (
            extension.key_agreement and any((extension.encipher_only, extension.decipher_only))
        ):
            raise ValidationError(INVALID_KEY_USAGE)
        return builder

    @classmethod
    def _build_certificate(
        cls,
        *,
        private_key: ManagedECPrivateKey,
        certificate_data: TraceabilityCertificateData,
        digest: EvidenceDigest,
    ) -> x509.Certificate:
        public_key = private_key.public_key()
        builder = certificate_data.certificate_builder or x509.CertificateBuilder()
        subject = certificate_data.subject
        if certificate_data.certificate_builder is not None:
            builder_subject = certificate_data.certificate_builder._subject_name  # noqa: SLF001
            if builder_subject is not None:
                subject = builder_subject
        if certificate_data.certificate_builder is None:
            builder = (
                builder.subject_name(subject)
                .not_valid_before(certificate_data.not_valid_before)
                .not_valid_after(certificate_data.not_valid_after)
            )
        existing_extensions = {
            extension.oid: extension.value for extension in builder._extensions  # noqa: SLF001
        }
        extension_oids = set(existing_extensions)
        builder = cls._apply_basic_constraints(builder, existing_extensions)
        builder = cls._apply_key_usage(builder, existing_extensions)

        if ExtensionOID.SUBJECT_KEY_IDENTIFIER not in extension_oids:
            builder = builder.add_extension(x509.SubjectKeyIdentifier.from_public_key(public_key), critical=False)
        if ExtensionOID.AUTHORITY_KEY_IDENTIFIER not in extension_oids:
            builder = builder.add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(public_key), critical=False
            )
        return builder.issuer_name(subject).serial_number(x509.random_serial_number()).public_key(public_key).sign(
            private_key, digest
        )

    @staticmethod
    def _default_certificate_data(
        name: str,
        validity_days: int,
    ) -> TraceabilityCertificateData:
        now = datetime.datetime.now(datetime.UTC)
        return TraceabilityCertificateData(
            subject=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)]),
            not_valid_before=now - datetime.timedelta(minutes=1),
            not_valid_after=now + datetime.timedelta(days=validity_days),
        )

    @staticmethod
    def _require_ec_key(private_key: object) -> ManagedECPrivateKey:
        """Require the configured backend to return an EC managed key."""
        if not isinstance(private_key, ManagedECPrivateKey):
            raise ValidationError(EC_KEY_REQUIRED)
        return private_key

    @classmethod
    @transaction.atomic
    def create(
        cls,
        *,
        name: str,
        curve: TraceabilityCredentialModel.Curve,
        purposes: Sequence[TraceabilityCredentialModel.Purpose],
        description: str = '',
        certificate_data: TraceabilityCertificateData | None = None,
    ) -> TraceabilityCredentialModel:
        """Create generation one and its logical Traceability Credential."""
        if TraceabilityCredentialModel.objects.filter(name=name).exists():
            raise ValidationError(NAME_NOT_UNIQUE)
        cls._validate_canonical_profile()
        normalized_purposes = sorted({str(purpose) for purpose in purposes})
        logical = TraceabilityCredentialModel(
            name=name,
            description=description,
            curve=curve,
            purposes=normalized_purposes,
        )
        logical.full_clean(exclude=['current_generation', 'retired_at'])
        curve_name, digest, _ = cls._curve_values(curve)
        private_key = generate_managed_signing_private_key(
            alias=f'traceability-signing:{name}:generation-1',
            key_spec=EcKeySpec(curve=curve_name),
        )
        try:
            private_key = cls._require_ec_key(private_key)
            cert = cls._build_certificate(
                private_key=private_key,
                certificate_data=certificate_data or cls._default_certificate_data(name, 365),
                digest=digest,
            )
            managed_key = CryptoManagedKeyModel.objects.get(pk=private_key.managed_key_ref.id)
            credential = CredentialModel.save_managed_key_credential(
                certificate=cert,
                certificate_chain=[],
                credential_type=CredentialModel.CredentialTypeChoice.EVIDENCE_SIGNING_CREDENTIAL,
                managed_key=managed_key,
            )
            now = datetime.datetime.now(datetime.UTC)
            logical.save()
            generation = TraceabilityCredentialGenerationModel.objects.create(
                traceability_credential=logical,
                credential=credential,
                generation_number=1,
                status=TraceabilityCredentialGenerationModel.Status.ACTIVE,
                activated_at=now,
            )
            logical.current_generation = generation
            logical.save(update_fields=['current_generation', 'updated_at'])
        except Exception:
            cls._cleanup_backend_key(private_key)
            raise
        return logical

    @staticmethod
    def _cleanup_backend_key(private_key: object) -> None:
        """Best-effort cleanup for a key whose database transaction failed."""
        if not isinstance(private_key, ManagedECPrivateKey):
            return
        with suppress(CryptoError, RuntimeError, TypeError, ValueError):
            TrustpointCryptoBackend().destroy_managed_key(private_key.managed_key_ref)

    @classmethod
    def sign(
        cls,
        *,
        traceability_credential: TraceabilityCredentialModel,
        data: bytes,
        purpose: TraceabilityCredentialModel.Purpose,
    ) -> TraceabilitySigningResult:
        """Sign raw bytes using the active generation and its fixed curve hash."""
        if purpose not in traceability_credential.purposes:
            raise ValidationError(PURPOSE_NOT_ASSIGNED)
        generation = traceability_credential.current_generation
        if not traceability_credential.is_usable or generation is None:
            raise ValidationError(NOT_USABLE)
        credential = generation.credential
        if credential.credential_type != CredentialModel.CredentialTypeChoice.EVIDENCE_SIGNING_CREDENTIAL:
            raise ValidationError(INVALID_TYPE)
        _, digest, algorithm = cls._curve_values(traceability_credential.curve)
        private_key = credential.get_private_key()
        if not isinstance(private_key, ManagedECPrivateKey):
            raise ValidationError(EC_KEY_REQUIRED)
        signature = private_key.sign(data, ec.ECDSA(digest))
        certificate = credential.certificate_or_error
        return TraceabilitySigningResult(
            signature=signature,
            traceability_credential_id=traceability_credential.pk,
            traceability_credential_name=traceability_credential.name,
            generation_id=generation.pk,
            certificate_id=certificate.pk,
            certificate_fingerprint_sha256=certificate.sha256_fingerprint,
            algorithm=algorithm,
        )

    @classmethod
    @transaction.atomic
    def rotate(
        cls,
        *,
        traceability_credential: TraceabilityCredentialModel,
        certificate_data: TraceabilityCertificateData | None = None,
    ) -> TraceabilityCredentialGenerationModel:
        """Create and activate a fresh generation while retiring the previous one."""
        logical = TraceabilityCredentialModel.objects.select_for_update().get(
            pk=traceability_credential.pk
        )
        if logical.status != TraceabilityCredentialModel.Status.ACTIVE:
            raise ValidationError(NOT_USABLE)
        cls._validate_canonical_profile()
        previous = logical.current_generation
        if previous is None:
            raise ValidationError(NOT_USABLE)
        generation_number = (
            logical.generations.order_by('-generation_number').values_list('generation_number', flat=True).first() or 0
        ) + 1
        curve_name, digest, _ = cls._curve_values(logical.curve)
        private_key = generate_managed_signing_private_key(
            alias=f'traceability-signing:{logical.name}:generation-{generation_number}',
            key_spec=EcKeySpec(curve=curve_name),
        )
        try:
            private_key = cls._require_ec_key(private_key)
            cert = cls._build_certificate(
                private_key=private_key,
                certificate_data=certificate_data or cls._default_certificate_data(logical.name, 365),
                digest=digest,
            )
            managed_key = CryptoManagedKeyModel.objects.get(pk=private_key.managed_key_ref.id)
            credential = CredentialModel.save_managed_key_credential(
                certificate=cert,
                certificate_chain=[],
                credential_type=CredentialModel.CredentialTypeChoice.EVIDENCE_SIGNING_CREDENTIAL,
                managed_key=managed_key,
            )
            now = datetime.datetime.now(datetime.UTC)
            previous.status = TraceabilityCredentialGenerationModel.Status.RETIRED
            previous.retired_at = now
            previous.save(update_fields=['status', 'retired_at'])
            generation = TraceabilityCredentialGenerationModel.objects.create(
                traceability_credential=logical,
                credential=credential,
                generation_number=generation_number,
                status=TraceabilityCredentialGenerationModel.Status.ACTIVE,
                activated_at=now,
            )
            logical.current_generation = generation
            logical.save(update_fields=['current_generation', 'updated_at'])
        except Exception:
            cls._cleanup_backend_key(private_key)
            raise
        return generation

    @staticmethod
    @transaction.atomic
    def retire(traceability_credential: TraceabilityCredentialModel) -> None:
        """Retire a logical credential and its current generation irreversibly."""
        logical = TraceabilityCredentialModel.objects.select_for_update().get(
            pk=traceability_credential.pk
        )
        if logical.status == TraceabilityCredentialModel.Status.RETIRED:
            raise ValidationError(ALREADY_RETIRED)
        generation = logical.current_generation
        if generation is None:
            raise ValidationError(NOT_USABLE)
        now = datetime.datetime.now(datetime.UTC)
        generation.status = TraceabilityCredentialGenerationModel.Status.RETIRED
        generation.retired_at = now
        generation.save(update_fields=['status', 'retired_at'])
        logical.status = TraceabilityCredentialModel.Status.RETIRED
        logical.retired_at = now
        logical.save(update_fields=['status', 'retired_at', 'updated_at'])

    @staticmethod
    @transaction.atomic
    def update_description(
        traceability_credential: TraceabilityCredentialModel,
        description: str,
    ) -> TraceabilityCredentialModel:
        """Update the only mutable normal metadata field."""
        logical = TraceabilityCredentialModel.objects.select_for_update().get(
            pk=traceability_credential.pk
        )
        logical.description = description
        logical.save(update_fields=['description', 'updated_at'])
        return logical

    @classmethod
    def verify(
        cls,
        *,
        generation: TraceabilityCredentialGenerationModel,
        data: bytes,
        signature: bytes,
        purpose: TraceabilityCredentialModel.Purpose,
    ) -> TraceabilityVerificationResult:
        """Verify a signature against the exact historical generation."""
        logical = generation.traceability_credential
        certificate = generation.credential.certificate_or_error
        _, digest, algorithm = cls._curve_values(logical.curve)
        result = TraceabilityVerificationResult(
            valid=False,
            traceability_credential_id=logical.pk,
            traceability_credential_name=logical.name,
            generation_id=generation.pk,
            certificate_id=certificate.pk,
            certificate_fingerprint_sha256=certificate.sha256_fingerprint,
            algorithm=algorithm,
        )
        if purpose not in logical.purposes:
            return result.__class__(**{**result.__dict__, 'failure_reason': VerificationFailureReason.PURPOSE_MISMATCH})
        try:
            certificate_obj = certificate.get_certificate_serializer().as_crypto()
            public_key = certificate_obj.public_key()
            if not isinstance(public_key, ec.EllipticCurvePublicKey):
                return replace(result, failure_reason=VerificationFailureReason.UNSUPPORTED_ALGORITHM)
            public_key.verify(signature, data, ec.ECDSA(digest))
        except InvalidSignature:
            return replace(result, failure_reason=VerificationFailureReason.INVALID_SIGNATURE)
        return replace(result, valid=True)
