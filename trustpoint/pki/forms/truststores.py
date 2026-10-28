# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Django forms for truststore configuration and management."""

from __future__ import annotations

import itertools
from typing import TYPE_CHECKING, Any, NoReturn, cast

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from django import forms
from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _
from trustpoint_core.serializer import (
    CertificateCollectionSerializer,
    CertificateSerializer,
)

from management.models import SecurityConfig
from pki.models.certificate import CertificateModel
from pki.models.truststore import TruststoreModel, TruststoreOrderModel
from pki.util.x509 import CertificateVerifier
from util.field import UniqueNameValidator, get_certificate_name

if TYPE_CHECKING:
    from pki.models.ca import CaModel


class TruststoreAddForm(forms.Form):
    """Form for adding a new truststore.

    This form handles the creation of a truststore by validating the unique name,
    intended usage, and uploaded file. It ensures the unique name is not already
    used and validates the truststore file content before saving.

    Attributes:
        unique_name (CharField): A unique name for the truststore.
        intended_usage (ChoiceField): Specifies the intended usage of the truststore.
        trust_store_file (FileField): The PEM or PKCS#7 file to be uploaded.
    """

    unique_name = forms.CharField(
        max_length=256,
        label=_('[Optional] Unique Name'),
        widget=forms.TextInput(attrs={'autocomplete': 'nope'}),
        required=False,
        validators=[UniqueNameValidator()],
    )

    intended_usage = forms.ChoiceField(
        choices=TruststoreModel.IntendedUsage,
        label=_('Intended Usage'),
        widget=forms.Select(attrs={'class': 'form-control'}),
        required=True,
    )

    trust_store_file = forms.FileField(label=_('PEM, DER, or PKCS#7 File'), required=True)

    def clean_unique_name(self) -> str:
        """Validate the uniqueness of the truststore name.

        Raises:
            ValidationError: If the name is already used by an existing truststore.
        """
        unique_name = self.cleaned_data['unique_name']
        if TruststoreModel.objects.filter(unique_name=unique_name).exists():
            error_message = 'Truststore with the provided name already exists.'
            raise ValidationError(error_message)
        return cast('str', unique_name)

    def _raise_validation_error(self, message: str) -> NoReturn:
        """Raise a form validation error."""
        raise ValidationError(message)

    def clean(self) -> None:
        """Clean and validate the uploaded truststore."""
        cleaned_data = cast('dict[str, Any]', super().clean())
        unique_name = cleaned_data.get('unique_name')
        intended_usage = str(cleaned_data.get('intended_usage'))

        trust_store_file = cleaned_data.get('trust_store_file')
        if trust_store_file is None:
            self._raise_validation_error('Truststore file is required.')

        try:
            trust_store_file = cast('bytes', trust_store_file.read())
        except (OSError, AttributeError) as original_exception:
            error_message = _(
                'Unexpected error occurred while trying to get file contents. Please see logs for further details.'
            )
            raise ValidationError(error_message, code='unexpected-error') from original_exception

        try:
            certificate_collection_serializer = CertificateCollectionSerializer.from_bytes(trust_store_file)
        except Exception:  # noqa: BLE001
            try:
                certificate_serializer = CertificateSerializer.from_bytes(trust_store_file)
                certificate_collection_serializer = CertificateCollectionSerializer(
                    [certificate_serializer.as_crypto()]
                )
            except Exception as exception:
                error_message = _('Unable to process the Truststore. May be malformed / corrupted.')
                raise ValidationError(error_message) from exception

        try:
            certs = certificate_collection_serializer.as_crypto()
            if not certs:
                self._raise_validation_error('Truststore cannot be empty.')
            if not unique_name:
                unique_name = get_certificate_name(certs[0])

            if TruststoreModel.objects.filter(unique_name=unique_name).exists():
                self._raise_validation_error('Truststore with the provided name already exists.')

            intended_usage_enum = TruststoreModel.IntendedUsage(int(intended_usage))
            validate_and_create_ca_chain(certs, intended_usage_enum)

            trust_store_model = self.save_trust_store(
                unique_name=unique_name,
                intended_usage=intended_usage_enum,
                certificates=certs,
            )
        except ValidationError:
            raise
        except Exception as exc:
            raise ValidationError(_('Failed to save the Truststore.')) from exc

        self.cleaned_data['truststore'] = trust_store_model

    @staticmethod
    def save_trust_store(
        unique_name: str,
        intended_usage: TruststoreModel.IntendedUsage,
        certificates: list[x509.Certificate],
    ) -> TruststoreModel:
        """Save all certificates of a truststore."""
        saved_certs: list[CertificateModel] = []

        for certificate in certificates:
            sha256_fingerprint = certificate.fingerprint(algorithm=hashes.SHA256()).hex().upper()
            try:
                saved_certs.append(CertificateModel.objects.get(sha256_fingerprint=sha256_fingerprint))
            except CertificateModel.DoesNotExist:
                saved_certs.append(CertificateModel.save_certificate(certificate))

        trust_store_model = TruststoreModel(unique_name=unique_name, intended_usage=intended_usage)
        trust_store_model.save()

        for number, certificate_model in enumerate(saved_certs):
            trust_store_order_model = TruststoreOrderModel()
            trust_store_order_model.order = number
            trust_store_order_model.certificate = certificate_model
            trust_store_order_model.trust_store = trust_store_model
            trust_store_order_model.save()

        return trust_store_model


def validate_and_create_ca_chain(
    certificates: list[x509.Certificate], intended_usage: TruststoreModel.IntendedUsage
) -> CaModel | None:
    """Validate an issuing-CA chain and create keyless CA models for its issuers.

    Validation is deliberately fail-closed. The chain must include exactly one
    complete leaf-to-root path, every certificate must be a valid CA certificate,
    every signature must verify, path-length constraints must be respected, and
    the active security policy must be unambiguous.
    """
    if intended_usage != TruststoreModel.IntendedUsage.ISSUING_CA_CHAIN:
        return None

    if not certificates:
        raise ValidationError(_('Truststore for Issuing CA Chain cannot be empty.'))

    sorted_certs = _sort_certificate_chain(certificates)
    if not sorted_certs:
        raise ValidationError(
            _('Unable to validate certificate chain. The certificates do not form a single complete chain.')
        )

    if not _validate_chain_integrity(sorted_certs):
        raise ValidationError(
            _('Invalid certificate chain. Each certificate must be cryptographically signed by the next certificate.')
        )

    root = sorted_certs[-1]
    if root.issuer != root.subject:
        raise ValidationError(
            _('Incomplete certificate chain. The chain must end with a self-signed root CA certificate.')
        )

    try:
        root.verify_directly_issued_by(root)
    except (InvalidSignature, ValueError) as exc:
        raise ValidationError(_('The root CA certificate is not validly self-signed.')) from exc

    _validate_security_policy_is_unambiguous()
    _validate_ca_semantics_and_policy(sorted_certs)
    _validate_path_length_constraints(sorted_certs)

    parent_ca = None
    issuer_ca = None
    for cert in reversed(sorted_certs[1:]):
        ca_model = _create_or_get_keyless_ca(cert, parent_ca)
        parent_ca = ca_model
        if issuer_ca is None:
            issuer_ca = ca_model

    return issuer_ca


def _validate_security_policy_is_unambiguous() -> None:
    """Require exactly one SecurityConfig before trust-establishing imports."""
    try:
        SecurityConfig.objects.get()
    except SecurityConfig.DoesNotExist as exc:
        raise ValidationError(
            _('No SecurityConfig is configured. Trust-establishing CA-chain imports are blocked.')
        ) from exc
    except SecurityConfig.MultipleObjectsReturned as exc:
        raise ValidationError(
            _('Multiple SecurityConfig rows are configured. Trust-establishing CA-chain imports are blocked.')
        ) from exc


def _validate_ca_semantics_and_policy(sorted_certs: list[x509.Certificate]) -> None:
    """Validate CA semantics, validity, algorithms, and the complete path for every certificate."""
    root = sorted_certs[-1]
    intermediates = sorted_certs[1:-1]

    for cert in sorted_certs:
        try:
            CertificateVerifier.verify_ca_cert(
                cert,
                trusted_roots=[root],
                untrusted_intermediates=intermediates,
            )
        except (TypeError, ValueError) as exc:
            subject = cert.subject.rfc4514_string()
            raise ValidationError(
                _('CA certificate %(subject)s violates certificate or security policy: %(reason)s'),
                params={'subject': subject, 'reason': str(exc)},
            ) from exc


def _validate_path_length_constraints(sorted_certs: list[x509.Certificate]) -> None:
    """Enforce BasicConstraints.path_length for all CA certificates in the path."""
    for index, cert in enumerate(sorted_certs):
        try:
            constraints = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
        except x509.ExtensionNotFound as exc:
            raise ValidationError(_('CA certificate is missing required BasicConstraints.')) from exc

        if not constraints.ca:
            raise ValidationError(_('Certificate in issuing CA chain has BasicConstraints.ca=False.'))

        if constraints.path_length is not None and index > constraints.path_length:
            subject = cert.subject.rfc4514_string()
            raise ValidationError(
                _('CA certificate %(subject)s violates its BasicConstraints.path_length constraint.'),
                params={'subject': subject},
            )


def _sort_certificate_chain(certificates: list[x509.Certificate]) -> list[x509.Certificate]:
    """Sort certificates from leaf to root and reject ambiguous or extra certificates."""
    if len(certificates) == 1:
        return certificates

    cert_by_subject: dict[bytes, x509.Certificate] = {}
    for cert in certificates:
        subject = cert.subject.public_bytes()
        if subject in cert_by_subject:
            return []
        cert_by_subject[subject] = cert

    issuer_subjects = {cert.issuer.public_bytes() for cert in certificates}
    leaf_candidates = [cert for cert in certificates if cert.subject.public_bytes() not in issuer_subjects]
    if len(leaf_candidates) != 1:
        return []

    chain = [leaf_candidates[0]]
    current = leaf_candidates[0]

    while True:
        issuer_subject = current.issuer.public_bytes()
        if issuer_subject == current.subject.public_bytes():
            return chain if len(chain) == len(certificates) else []

        next_cert = cert_by_subject.get(issuer_subject)
        if next_cert is None or next_cert in chain:
            return []

        chain.append(next_cert)
        current = next_cert
        if len(chain) > len(certificates):
            return []


def _validate_chain_integrity(sorted_certs: list[x509.Certificate]) -> bool:
    """Cryptographically verify every adjacent certificate signature in a sorted chain."""
    for cert, issuer_cert in itertools.pairwise(sorted_certs):
        if cert.issuer != issuer_cert.subject:
            return False
        try:
            cert.verify_directly_issued_by(issuer_cert)
        except (InvalidSignature, ValueError):
            return False
    return True


def _create_or_get_keyless_ca(cert: x509.Certificate, parent_ca: CaModel | None = None) -> CaModel:
    """Create or get a keyless CA model for the given certificate."""
    from pki.models.ca import CaModel  # noqa: PLC0415

    sha256_fingerprint = cert.fingerprint(algorithm=hashes.SHA256()).hex().upper()

    existing_ca = CaModel.objects.filter(certificate__sha256_fingerprint=sha256_fingerprint).first()
    if existing_ca:
        if parent_ca and not existing_ca.parent_ca:
            existing_ca.parent_ca = parent_ca
            existing_ca.save(update_fields=['parent_ca'])
        return existing_ca

    try:
        cert_model = CertificateModel.objects.get(sha256_fingerprint=sha256_fingerprint)
    except CertificateModel.DoesNotExist:
        cert_model = CertificateModel.save_certificate(cert)

    try:
        cn_attrs = cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
        if cn_attrs:
            cn_value = cn_attrs[0].value
            common_name = cn_value.decode('utf-8') if isinstance(cn_value, bytes) else cn_value
        else:
            msg = 'Common Name (CN) is mandatory for CA certificates.'
            raise ValidationError(msg)
    except AttributeError as exc:
        msg = f'Failed to extract Common Name (CN) from certificate: {exc}'
        raise ValidationError(msg) from exc

    unique_name = common_name
    counter = 1
    while CaModel.objects.filter(unique_name=unique_name).exists():
        unique_name = f'{common_name}-{counter}'
        counter += 1

    ca = CaModel(
        unique_name=unique_name,
        ca_type=CaModel.CaTypeChoice.KEYLESS,
        certificate=cert_model,
        parent_ca=parent_ca,
        is_active=True,
    )
    ca.save()

    return ca


class TruststoreDownloadForm(forms.Form):
    """Form for downloading truststores in various formats."""

    cert_file_container = forms.ChoiceField(
        label=_('Select Truststore Container Type'),
        choices=[
            ('single_file', _('Single File')),
            ('zip', _('Separate Certificate Files (as .zip file)')),
            ('tar_gz', _('Separate Certificate Files (as .tar.gz file)')),
        ],
        initial='single_file',
        required=True,
    )

    cert_chain_incl = forms.ChoiceField(
        label=_('Select Included Certificates'),
        choices=[('cert_only', _('Selected certificates only')), ('chain_incl', _('Include certificate chains'))],
        initial='selected_cert_only',
        required=True,
    )

    cert_file_format = forms.ChoiceField(
        label=_('Select Truststore File Format'),
        choices=[
            ('pem', _('PEM (.pem, .crt, .ca-bundle)')),
            ('der', _('DER (.der, .cer)')),
            ('pkcs7_pem', _('PKCS#7 (PEM) (.p7b, .p7c, .keystore)')),
            ('pkcs7_der', _('PKCS#7 (DER) (.p7b, .p7c, .keystore)')),
        ],
        initial='pem',
        required=True,
    )
