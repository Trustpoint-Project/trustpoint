# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Lifecycle and cryptographic operations for Traceability Credentials."""

from __future__ import annotations

import datetime as dt
from contextlib import suppress
from dataclasses import dataclass, replace
from enum import StrEnum
from typing import TYPE_CHECKING, Any, cast
from uuid import uuid4

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, ExtensionOID
from django.core.exceptions import ValidationError
from django.db import IntegrityError, transaction

from crypto.application.private_keys import ManagedECPrivateKey, generate_managed_signing_private_key
from crypto.application.service import TrustpointCryptoBackend
from crypto.domain.algorithms import EllipticCurveName
from crypto.domain.errors import CryptoError
from crypto.domain.policies import KeyPolicy, SigningExecutionMode
from crypto.domain.public_keys import public_key_fingerprint_sha256
from crypto.domain.specs import EcKeySpec
from crypto.models import CryptoManagedKeyModel
from management.models.traceability import (
    TraceabilityCredentialGenerationModel,
    TraceabilityCredentialModel,
)
from pki.models.cert_profile import CertificateProfileModel
from pki.models.credential import CredentialModel
from pki.services.external_csr import build_external_csr, finalize_external_certificate
from pki.services.management_issuance import (
    available_management_cas,
    key_type_for_management_ca,
    sign_certificate_request,
)
from pki.services.tls_server_issuance import issue_tls_server_remote
from pki.util.cert_req_converter import _eku_oid_from_str
from pki.util.certificate_path import validate_issued_certificate_path

if TYPE_CHECKING:
    from pki.models import CaModel
    from pki.models.truststore import TruststoreModel

type EvidenceDigest = hashes.SHA256 | hashes.SHA384


UNSUPPORTED_CURVE = 'Unsupported Traceability Credential curve.'
EC_KEY_REQUIRED = 'Traceability Credentials require an EC backend key.'
NOT_USABLE = 'Traceability Credential is not currently usable.'
INVALID_TYPE = 'Invalid Traceability Credential type.'
ONE_ACTIVE = 'Only one traceability credential can be active. Retire the current credential first.'
ALREADY_RETIRED = 'Traceability Credential is already retired.'
INVALID_PROFILE = 'The canonical Traceability Credential profile is missing or invalid.'
INVALID_BASIC_CONSTRAINTS = 'Traceability Credential profile must set CA=false.'
INVALID_KEY_USAGE = 'Traceability Credential profile must allow digitalSignature only.'
INVALID_EXTENDED_KEY_USAGE = 'Extended Key Usage must permit traceability signing (anyExtendedKeyUsage).'


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
        eku = extensions.get('extended_key_usage')
        if eku is not None:
            if not isinstance(eku, dict) or not isinstance(eku.get('usages'), list):
                raise ValidationError(INVALID_PROFILE)
            try:
                usage = x509.ExtendedKeyUsage([_eku_oid_from_str(value) for value in eku['usages']])
            except (AttributeError, TypeError, ValueError) as error:
                raise ValidationError(INVALID_PROFILE) from error
            TraceabilityCredentialService._validate_extended_key_usage(usage)

    @staticmethod
    def _validate_extended_key_usage(usage: x509.ExtendedKeyUsage | None) -> None:
        """Honor purpose restrictions; no dedicated traceability purpose OID is defined yet."""
        if usage is not None and ExtendedKeyUsageOID.ANY_EXTENDED_KEY_USAGE not in usage:
            raise ValidationError(INVALID_EXTENDED_KEY_USAGE)

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
        management_ca: CaModel,
        description: str = '',
    ) -> TraceabilityCredentialModel:
        """Configure and initially issue a traceability identity from a management CA."""
        logical = cls.configure(
            name=name,
            description=description,
            management_ca=management_ca,
            assignment_method=TraceabilityCredentialModel.AssignmentMethod.MANAGEMENT_CA,
        )
        cls.request_credential(logical, content={'common_name': name})
        logical.refresh_from_db()
        return logical

    @staticmethod
    def _ensure_single_active(logical: TraceabilityCredentialModel) -> None:
        active = TraceabilityCredentialModel.objects.filter(
            status=TraceabilityCredentialModel.Status.ACTIVE,
        ).exclude(pk=logical.pk)
        if active.exists():
            raise ValidationError(ONE_ACTIVE)

    @classmethod
    @transaction.atomic
    def configure(
        cls,
        *,
        name: str,
        curve: str = '',
        assignment_method: str,
        description: str = '',
        management_ca: CaModel | None = None,
    ) -> TraceabilityCredentialModel:
        """Persist an abstract identity before any key or certificate is assigned."""
        if assignment_method not in TraceabilityCredentialModel.AssignmentMethod.values:
            msg = 'Select a credential assignment method.'
            raise ValidationError(msg)
        if assignment_method == TraceabilityCredentialModel.AssignmentMethod.MANAGEMENT_CA:
            curve = cls.management_ca_curve(management_ca)
        logical = TraceabilityCredentialModel(
            name=name,
            curve=curve,
            description=description,
            assignment_method=assignment_method,
            management_ca=management_ca,
        )
        logical.full_clean()
        logical.save()
        return logical

    @staticmethod
    def management_ca_curve(ca: CaModel | None) -> TraceabilityCredentialModel.Curve:
        """Bind traceability keys to a supported management CA curve."""
        if ca is None or not ca.is_management_ca or not ca.is_active:
            message = 'Select an active management CA / RA.'
            raise ValidationError(message)
        curves = {
            'ECC-SECP256R1': TraceabilityCredentialModel.Curve.SECP256R1,
            'ECC-SECP384R1': TraceabilityCredentialModel.Curve.SECP384R1,
        }
        try:
            key_type = key_type_for_management_ca(ca, [(key, key) for key in curves])
        except ValidationError as error:
            message = 'Select a management CA / RA with a supported P-256 or P-384 signing key.'
            raise ValidationError(message) from error
        return curves[key_type]

    @classmethod
    def _validate_certificate(cls, logical: TraceabilityCredentialModel, certificate: x509.Certificate) -> None:
        """Reject unsuitable signing certificates and reuse of any historical key."""
        public_key = certificate.public_key()
        curves = {
            TraceabilityCredentialModel.Curve.SECP256R1: 'secp256r1',
            TraceabilityCredentialModel.Curve.SECP384R1: 'secp384r1',
        }
        if not isinstance(public_key, ec.EllipticCurvePublicKey) or public_key.curve.name not in curves.values():
            raise ValidationError(UNSUPPORTED_CURVE)
        if logical.curve and public_key.curve.name != curves[TraceabilityCredentialModel.Curve(logical.curve)]:
            msg = 'The certificate key must match the configured traceability curve.'
            raise ValidationError(msg)
        now = dt.datetime.now(dt.UTC)
        if not certificate.not_valid_before_utc <= now < certificate.not_valid_after_utc:
            msg = 'The traceability certificate must be currently valid.'
            raise ValidationError(msg)
        try:
            extensions = {extension.oid: extension.value for extension in certificate.extensions}
            if ExtensionOID.BASIC_CONSTRAINTS not in extensions or ExtensionOID.KEY_USAGE not in extensions:
                msg = 'The certificate requires BasicConstraints and KeyUsage extensions.'
                raise ValidationError(msg)
            constraints = extensions[ExtensionOID.BASIC_CONSTRAINTS]
            usage = extensions[ExtensionOID.KEY_USAGE]
            if constraints.ca:
                raise ValidationError(INVALID_BASIC_CONSTRAINTS)
            if not usage.digital_signature or any(
                (
                    usage.content_commitment,
                    usage.key_encipherment,
                    usage.data_encipherment,
                    usage.key_agreement,
                    usage.key_cert_sign,
                    usage.crl_sign,
                )
            ):
                raise ValidationError(INVALID_KEY_USAGE)
            cls._validate_extended_key_usage(extensions.get(ExtensionOID.EXTENDED_KEY_USAGE))
        except (ValueError, x509.DuplicateExtension) as error:
            msg = 'Invalid traceability certificate extensions.'
            raise ValidationError(msg) from error
        # Include retired identities so configuring another cannot bypass key rotation.
        if TraceabilityCredentialGenerationModel.objects.filter(
            credential__managed_private_key__public_key_fingerprint_sha256=public_key_fingerprint_sha256(public_key),
        ).exists():
            message = 'A replacement traceability credential must use a new key and certificate.'
            raise ValidationError(message)

    @classmethod
    def _activate(
        cls,
        logical: TraceabilityCredentialModel,
        credential: CredentialModel,
    ) -> TraceabilityCredentialGenerationModel:
        """Atomically retire the previous generation only after the replacement is valid."""
        cls._ensure_single_active(logical)
        cls._validate_certificate(logical, credential.get_certificate())
        credential.full_clean()
        now = dt.datetime.now(dt.UTC)
        number = (
            logical.generations.order_by('-generation_number')
            .values_list(
                'generation_number',
                flat=True,
            )
            .first()
            or 0
        ) + 1
        try:
            with transaction.atomic():
                if logical.current_generation is not None:
                    previous = logical.current_generation
                    if previous.status == previous.Status.ACTIVE:
                        previous.status = previous.Status.RETIRED
                        previous.retired_at = now
                        previous.save(update_fields=['status', 'retired_at'])
                generation = TraceabilityCredentialGenerationModel.objects.create(
                    traceability_credential=logical,
                    credential=credential,
                    generation_number=number,
                    status=TraceabilityCredentialGenerationModel.Status.ACTIVE,
                    activated_at=now,
                )
                if not logical.curve:
                    public_key = cast('ec.EllipticCurvePublicKey', credential.get_certificate().public_key())
                    logical.curve = (
                        logical.Curve.SECP256R1
                        if isinstance(public_key.curve, ec.SECP256R1)
                        else logical.Curve.SECP384R1
                    )
                logical.current_generation = generation
                logical.status = logical.Status.ACTIVE
                logical.retired_at = None
                logical.pending_credential = None
                logical.pending_csr = ''
                logical.save(
                    update_fields=[
                        'curve',
                        'current_generation',
                        'status',
                        'retired_at',
                        'pending_credential',
                        'pending_csr',
                        'updated_at',
                    ]
                )
        except IntegrityError as error:
            raise ValidationError(ONE_ACTIVE) from error
        return generation

    @classmethod
    @transaction.atomic
    def request_credential(
        cls,
        logical: TraceabilityCredentialModel,
        *,
        content: dict[str, Any],
    ) -> TraceabilityCredentialGenerationModel | str:
        """Generate a fresh managed key for CA issuance or a persisted external CSR."""
        logical = TraceabilityCredentialModel.objects.select_for_update().get(pk=logical.pk)
        method = logical.assignment_method
        if method not in (logical.AssignmentMethod.MANAGEMENT_CA, logical.AssignmentMethod.CSR):
            msg = 'Upload a new credential using the configured assignment method.'
            raise ValidationError(msg)
        if logical.pending_credential_id is not None:
            msg = 'A CSR is already pending. Complete or cancel it before requesting another.'
            raise ValidationError(msg)
        cls._ensure_single_active(logical)
        cls._validate_canonical_profile()
        profile = CertificateProfileModel.objects.get(unique_name='traceability_credential')
        ca = logical.management_ca
        if method == logical.AssignmentMethod.MANAGEMENT_CA and (
            ca is None or not available_management_cas().filter(pk=ca.pk).exists()
        ):
            msg = 'Select an active management CA / RA with a usable certificate.'
            raise ValidationError(msg)
        if method == logical.AssignmentMethod.MANAGEMENT_CA and cls.management_ca_curve(ca) != logical.curve:
            message = 'The configured signing key curve no longer matches the management CA.'
            raise ValidationError(message)
        curve, _, _ = cls._curve_values(logical.curve)
        private_key = generate_managed_signing_private_key(
            alias=f'traceability-signing:{logical.pk}:{uuid4().hex}',
            key_spec=EcKeySpec(curve=curve),
        )
        try:
            with transaction.atomic():
                private_key = cls._require_ec_key(private_key)
                credential = CredentialModel.save_managed_private_key_credential(
                    credential_type=CredentialModel.CredentialTypeChoice.EVIDENCE_SIGNING_CREDENTIAL,
                    managed_key=CryptoManagedKeyModel.objects.get(pk=private_key.managed_key_ref.id),
                )
                csr = build_external_csr(credential, profile, content)
                if method == logical.AssignmentMethod.CSR:
                    logical.pending_credential = credential
                    logical.pending_csr = csr.public_bytes(serialization.Encoding.PEM).decode('ascii')
                    logical.save(update_fields=['pending_credential', 'pending_csr', 'updated_at'])
                    return logical.pending_csr
                ca = cast('CaModel', ca)
                if ca.is_issuing_ca:
                    certificate, chain = sign_certificate_request(csr, profile, ca)
                    finalize_external_certificate(credential, certificate, [certificate, *chain])
                else:
                    issue_tls_server_remote(credential, profile, content, ca)
                credential.refresh_from_db()
                cls._validate_requested_identity(credential.get_certificate(), csr)
                return cls._activate(logical, credential)
        except Exception:
            cls._cleanup_backend_key(private_key)
            raise

    @classmethod
    @transaction.atomic
    def import_credential(
        cls,
        logical: TraceabilityCredentialModel,
        *,
        private_key: ec.EllipticCurvePrivateKey,
        certificate: x509.Certificate,
        chain: list[x509.Certificate],
    ) -> TraceabilityCredentialGenerationModel:
        """Import a fresh signing key through the configured backend and activate it."""
        logical = TraceabilityCredentialModel.objects.select_for_update().get(pk=logical.pk)
        if logical.assignment_method not in (logical.AssignmentMethod.PKCS12, logical.AssignmentMethod.SEPARATE_FILES):
            msg = 'This identity is not configured for credential import.'
            raise ValidationError(msg)
        cls._ensure_single_active(logical)
        cls._validate_certificate(logical, certificate)
        if not isinstance(private_key, ec.EllipticCurvePrivateKey) or (
            public_key_fingerprint_sha256(private_key.public_key())
            != public_key_fingerprint_sha256(cast('ec.EllipticCurvePublicKey', certificate.public_key()))
        ):
            msg = 'The private key does not match the certificate.'
            raise ValidationError(msg)
        key_ref = TrustpointCryptoBackend().import_managed_private_key(
            alias=f'traceability-import:{logical.pk}:{x509.random_serial_number()}',
            private_key=private_key,
            policy=KeyPolicy.managed_signing_key(signing_execution_mode=SigningExecutionMode.ALLOW_APPLICATION_HASH),
        )
        try:
            with transaction.atomic():
                credential = CredentialModel.save_managed_key_credential(
                    certificate=certificate,
                    certificate_chain=chain,
                    credential_type=CredentialModel.CredentialTypeChoice.EVIDENCE_SIGNING_CREDENTIAL,
                    managed_key=CryptoManagedKeyModel.objects.get(pk=key_ref.id),
                )
                return cls._activate(logical, credential)
        except Exception:
            with suppress(CryptoError, RuntimeError, TypeError, ValueError):
                TrustpointCryptoBackend().destroy_managed_key(key_ref)
            raise

    @staticmethod
    def _validate_requested_identity(certificate: x509.Certificate, csr: x509.CertificateSigningRequest) -> None:
        """Reject an issuer changing the requested subject or SAN identities."""
        if certificate.subject != csr.subject:
            message = 'The issued certificate subject does not match the request.'
            raise ValidationError(message)

        def sans(value: x509.Certificate | x509.CertificateSigningRequest) -> x509.SubjectAlternativeName | None:
            try:
                return value.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
            except x509.ExtensionNotFound:
                return None

        if sans(certificate) != sans(csr):
            message = 'The issued certificate SANs do not match the request.'
            raise ValidationError(message)

    @classmethod
    @transaction.atomic
    def complete_csr(
        cls,
        logical: TraceabilityCredentialModel,
        *,
        certificate: x509.Certificate,
        truststore: TruststoreModel,
    ) -> TraceabilityCredentialGenerationModel:
        """Validate the returned certificate against its persisted key, request, and CA anchors."""
        logical = TraceabilityCredentialModel.objects.select_for_update().get(pk=logical.pk)
        if logical.assignment_method != logical.AssignmentMethod.CSR or logical.pending_credential is None:
            msg = 'There is no pending traceability CSR.'
            raise ValidationError(msg)
        csr = x509.load_pem_x509_csr(logical.pending_csr.encode('ascii'))
        cls._validate_requested_identity(certificate, csr)
        anchors = truststore.get_certificate_collection_serializer().as_crypto()
        chain = validate_issued_certificate_path(certificate, list(anchors), [])
        credential = logical.pending_credential
        finalize_external_certificate(credential, certificate, chain)
        credential.refresh_from_db()
        return cls._activate(logical, credential)

    @classmethod
    @transaction.atomic
    def cancel_csr(cls, logical: TraceabilityCredentialModel) -> None:
        """Discard the pending request without changing the currently active generation."""
        logical = TraceabilityCredentialModel.objects.select_for_update().get(pk=logical.pk)
        pending = logical.pending_credential
        if pending is None:
            msg = 'There is no pending traceability CSR.'
            raise ValidationError(msg)
        key = pending.get_private_key()
        logical.pending_credential = None
        logical.pending_csr = ''
        logical.save(update_fields=['pending_credential', 'pending_csr', 'updated_at'])
        pending.delete()
        # Destroy only after commit; a rolled-back cancellation must keep its pending key.
        transaction.on_commit(lambda: cls._cleanup_backend_key(key))

    @staticmethod
    def _cleanup_backend_key(private_key: object) -> None:
        """Best-effort cleanup for a key whose database transaction failed."""
        if not isinstance(private_key, ManagedECPrivateKey):
            return
        with suppress(CryptoError, RuntimeError, TypeError, ValueError):
            TrustpointCryptoBackend().destroy_managed_key(private_key.managed_key_ref)

    @classmethod
    @transaction.atomic
    def sign(
        cls,
        *,
        traceability_credential: TraceabilityCredentialModel,
        data: bytes,
    ) -> TraceabilitySigningResult:
        """Sign consumer-defined bytes; callers must encode the usage context in data."""
        traceability_credential = TraceabilityCredentialModel.objects.select_for_update().get(
            pk=traceability_credential.pk
        )
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
    def rotate(
        cls,
        *,
        traceability_credential: TraceabilityCredentialModel,
    ) -> TraceabilityCredentialGenerationModel:
        """Issue a fresh management CA generation using the saved configuration."""
        if traceability_credential.assignment_method != TraceabilityCredentialModel.AssignmentMethod.MANAGEMENT_CA:
            message = 'Request a CSR or upload a new credential using the configured assignment method.'
            raise ValidationError(message)
        result = cls.request_credential(traceability_credential, content={'common_name': traceability_credential.name})
        return cast('TraceabilityCredentialGenerationModel', result)

    @staticmethod
    @transaction.atomic
    def retire(traceability_credential: TraceabilityCredentialModel) -> None:
        """Stop signing with the current generation and cancel any pending CSR."""
        logical = TraceabilityCredentialModel.objects.select_for_update().get(pk=traceability_credential.pk)
        if logical.status == TraceabilityCredentialModel.Status.RETIRED:
            raise ValidationError(ALREADY_RETIRED)
        generation = logical.current_generation
        if generation is None:
            raise ValidationError(NOT_USABLE)
        now = dt.datetime.now(dt.UTC)
        generation.status = TraceabilityCredentialGenerationModel.Status.RETIRED
        generation.retired_at = now
        generation.save(update_fields=['status', 'retired_at'])
        if logical.pending_credential_id is not None:
            TraceabilityCredentialService.cancel_csr(logical)
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
        logical = TraceabilityCredentialModel.objects.select_for_update().get(pk=traceability_credential.pk)
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
    ) -> TraceabilityVerificationResult:
        """Verify the exact consumer-defined bytes against the historical generation."""
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
        try:
            certificate_obj = certificate.get_certificate_serializer().as_crypto()
            public_key = certificate_obj.public_key()
            if not isinstance(public_key, ec.EllipticCurvePublicKey):
                return replace(result, failure_reason=VerificationFailureReason.UNSUPPORTED_ALGORITHM)
            public_key.verify(signature, data, ec.ECDSA(digest))
        except InvalidSignature:
            return replace(result, failure_reason=VerificationFailureReason.INVALID_SIGNATURE)
        return replace(result, valid=True)
