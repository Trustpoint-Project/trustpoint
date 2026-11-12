# Copyright (c) 2024 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Module that contains the CredentialModel."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, ClassVar

from cryptography.hazmat.primitives.asymmetric import mldsa
from django.core.exceptions import ValidationError
from django.db import models, transaction
from django.utils.translation import gettext_lazy as _
from trustpoint_core import oid
from trustpoint_core.serializer import (
    CertificateCollectionSerializer,
    CertificateSerializer,
    CredentialSerializer,
    PrivateKeySerializer,
)

from crypto.application.private_keys import ManagedECPrivateKey, ManagedRSAPrivateKey, managed_private_key_for_ref
from crypto.application.service import TrustpointCryptoBackend
from crypto.models import CryptoManagedKeyModel
from pki.models import CertificateModel
from trustpoint.logger import LoggerMixin
from util.db import CustomDeleteActionModel
from util.encrypted_fields import EncryptedCharField

EVIDENCE_SIGNING_NO_PEM = 'Traceability Credentials cannot store a private-key PEM.'
EVIDENCE_SIGNING_NO_KEY = 'Traceability Credentials require a managed private key.'
EVIDENCE_SIGNING_NO_CERTIFICATE = 'Traceability Credentials require a certificate.'

if TYPE_CHECKING:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from django.db.models import QuerySet
    from trustpoint_core.crypto_types import PrivateKey

__all__ = [
    'CertificateChainOrderModel',
    'CredentialAlreadyExistsError',
    'CredentialModel',
    'IDevIDReferenceModel',
    'PrimaryCredentialCertificate',
]


class CredentialAlreadyExistsError(ValidationError):
    """The CredentialAlreadyExistsError is raised if a credential already exists in the database."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """Initializes the CredentialAlreadyExistsError with a default message."""
        super().__init__(_('Credential already exists.'), *args, **kwargs)


class CredentialModel(LoggerMixin, CustomDeleteActionModel):
    """The CredentialModel that holds all local credentials used by the Trustpoint.

    This model holds local software credentials and credentials whose private key is owned by
    the configured Trustpoint crypto backend.
    """

    class CredentialTypeChoice(models.IntegerChoices):
        """The CredentialTypeChoice defines the type of the credential and thus implicitly restricts its usage.

        It is intended to limit the credential usage to specific cases, e.g. usage as Issuing CA.
        The abstractions using the CredentialModel are responsible to check that the credential has
        the correct and expected CredentialTypeChoice.
        """

        TRUSTPOINT_TLS_SERVER = 0, _('Trustpoint TLS Server')
        ROOT_CA = 1, _('Root CA')
        ISSUING_CA = 2, _('Issuing CA')
        ISSUED_CREDENTIAL = 3, _('Issued Credential')
        DEV_OWNER_ID = 4, _('DevOwnerID')
        SIGNER = 5, _('Signer')
        SCEP_SERVER = 6, _('SCEP Server')
        EVIDENCE_SIGNING_CREDENTIAL = 7, _('Traceability Credential')

    BACKEND_MANAGED_SIGNING_TYPES: ClassVar[frozenset[CredentialTypeChoice]] = frozenset(
        {
            CredentialTypeChoice.ROOT_CA,
            CredentialTypeChoice.ISSUING_CA,
            CredentialTypeChoice.EVIDENCE_SIGNING_CREDENTIAL,
        }
    )

    credential_type = models.IntegerField(verbose_name=_('Credential Type'), choices=CredentialTypeChoice)
    private_key = EncryptedCharField(verbose_name=_('Private key (PEM)'), max_length=9500, default='', blank=True)
    managed_private_key = models.ForeignKey(
        CryptoManagedKeyModel,
        on_delete=models.PROTECT,
        null=True,
        blank=True,
        verbose_name=_('Managed Private Key'),
        help_text=_('Reference to the configured Trustpoint crypto backend managed key'),
    )

    certificate = models.ForeignKey(
        CertificateModel, on_delete=models.PROTECT, related_name='credential_set', blank=True, null=True
    )

    certificates = models.ManyToManyField[CertificateModel, 'PrimaryCredentialCertificate'](
        CertificateModel, through='PrimaryCredentialCertificate', blank=True, related_name='credential'
    )
    certificate_chain: models.ManyToManyField[CertificateModel, CertificateChainOrderModel] = models.ManyToManyField(
        CertificateModel,
        blank=True,
        through='CertificateChainOrderModel',
        through_fields=('credential', 'certificate'),
        related_name='credential_certificate_chains',
    )

    created_at = models.DateTimeField(verbose_name=_('Created'), auto_now_add=True)

    def __repr__(self) -> str:
        """Returns a string representation of this CredentialModel entry."""
        return f'CredentialModel(credential_type={self.credential_type}, certificate=)'

    def __str__(self) -> str:
        """Returns a human-readable string that represents this CredentialModel entry.

        Returns:
            str: Human-readable string that represents this CredentialModel entry.
        """
        return self.__repr__()

    def clean(self) -> None:
        """Validates the CredentialModel instance."""
        if self.private_key and self.managed_private_key_id is not None:
            exc_msg = 'A credential cannot store both raw private-key PEM and a managed backend private key.'
            raise ValidationError(exc_msg)

        if self.private_key and self.credential_type in self.BACKEND_MANAGED_SIGNING_TYPES:
            exc_msg = (
                'Trustpoint signing credentials must use the configured crypto backend. '
                'Raw private-key PEM storage is only allowed for exported end-entity/TLS material.'
            )
            raise ValidationError(exc_msg)

        if self.credential_type == self.CredentialTypeChoice.EVIDENCE_SIGNING_CREDENTIAL:
            self._clean_traceability_credential()

        qs = self.primarycredentialcertificate_set.filter(is_primary=True)
        if qs.count() > 1:
            exc_msg = 'A credential can only have one primary certificate.'
            raise ValidationError(exc_msg)

        if self.certificate is None:
            if qs.exists():
                exc_msg = 'Cannot have primary certificates when certificate is not set.'
                raise ValidationError(exc_msg)
            return  # No further validation if certificate is None

        if qs.get().certificate != self.certificate:
            exc_msg = (
                'The ForeignKey certificate must be identical to the one '
                'marked primary in the primarycredentialcertificate_set.'
            )

            raise ValidationError(exc_msg)

    def _clean_traceability_credential(self) -> None:
        """Validate the storage boundary for an Traceability Credential."""
        if self.private_key:
            raise ValidationError(EVIDENCE_SIGNING_NO_PEM)
        if self.managed_private_key_id is None:
            raise ValidationError(EVIDENCE_SIGNING_NO_KEY)
        if self.certificate_id is None:
            raise ValidationError(EVIDENCE_SIGNING_NO_CERTIFICATE)

    @property
    def certificate_or_error(self) -> CertificateModel:
        """Returns the certificate, raising an error if it is None.

        Returns:
            CertificateModel: The non-null certificate.

        Raises:
            ValueError: If certificate is None.
        """
        if self.certificate is None:
            msg = f'Certificate is None for credential (type: {self.credential_type})'
            raise ValueError(msg)
        return self.certificate

    @classmethod
    def save_credential_serializer(
        cls, credential_serializer: CredentialSerializer, credential_type: CredentialModel.CredentialTypeChoice
    ) -> CredentialModel:
        """This method will try to normalize the credential_serializer and then save it to the database.

        Args:
            credential_serializer: The credential serializer to store in the database.
            credential_type: The credential type to set.

        Returns:
            CredentialModel: The stored credential model.
        """
        return cls._save_normalized_credential_serializer(
            normalized_credential_serializer=credential_serializer, credential_type=credential_type
        )

    @property
    def ordered_certificate_chain_queryset(self) -> QuerySet[CertificateChainOrderModel]:
        """Gets the ordered certificate chain queryset."""
        return self.certificatechainordermodel_set.order_by('order')

    @classmethod
    @transaction.atomic
    def _save_normalized_credential_serializer(
        cls,
        normalized_credential_serializer: CredentialSerializer,
        credential_type: CredentialModel.CredentialTypeChoice,
    ) -> CredentialModel:
        """This method will store a credential that is expected to be normalized."""
        cls.logger.info('Starting to save credential of type: %s', credential_type)
        certificate = cls._validate_and_save_certificate(normalized_credential_serializer)
        private_key_pem = cls._process_private_key(normalized_credential_serializer, credential_type)
        credential_model = cls._create_credential_model(certificate, credential_type, private_key_pem)
        additional_certificates = list(reversed(normalized_credential_serializer.additional_certificates))
        cls._save_additional_certificates(credential_model, additional_certificates)
        return credential_model

    @staticmethod
    def _validate_and_save_certificate(
        normalized_credential_serializer: CredentialSerializer,
    ) -> CertificateModel | None:
        """Validates and saves the certificate from the provided serializer.

        Args:
            normalized_credential_serializer (CredentialSerializer): The serializer containing
                the certificate to be validated and saved.

        Raises:
            ValueError: If the certificate in the serializer is None.

        Returns:
            CertificateModel | None: The saved certificate model instance, or None if no certificate is present.
        """
        # TODO(AlexHx8472): Verify that the credential is valid in respect to the credential_type!!!  # noqa: FIX002
        if normalized_credential_serializer.certificate is None:
            return None
        return CertificateModel.save_certificate(normalized_credential_serializer.certificate)

    @staticmethod
    def _process_private_key(
        normalized_credential_serializer: CredentialSerializer,
        credential_type: CredentialModel.CredentialTypeChoice,
    ) -> str:
        """Extract a software private key from a normalized serializer.

        Backend-owned keys are persisted through ``CryptoManagedKeyModel``. Serializer-level
        non-software serializer references are intentionally rejected so PKI code no longer
        imports or generates keys through backend-specific paths.
        """
        private_key_reference = normalized_credential_serializer.private_key_reference
        if private_key_reference is not None and credential_type in CredentialModel.BACKEND_MANAGED_SIGNING_TYPES:
            msg = (
                'Serializer-level private-key references are no longer supported for Trustpoint signing credentials. '
                'Use CryptoManagedKeyModel-backed credentials instead.'
            )
            raise ValueError(msg)

        private_key_serializer = normalized_credential_serializer.get_private_key_serializer()
        if private_key_serializer:
            if credential_type in CredentialModel.BACKEND_MANAGED_SIGNING_TYPES:
                msg = (
                    'Trustpoint signing credentials must be generated or imported through the configured '
                    'crypto backend before being linked to a CredentialModel.'
                )
                raise ValueError(msg)
            return private_key_serializer.as_pkcs8_pem().decode()
        return ''

    @classmethod
    def _create_credential_model(
        cls,
        certificate: CertificateModel | None,
        credential_type: CredentialModel.CredentialTypeChoice,
        private_key_pem: str,
        managed_private_key: CryptoManagedKeyModel | None = None,
    ) -> CredentialModel:
        """Creates and saves a CredentialModel instance."""
        credential_model = cls.objects.create(
            certificate=certificate,
            credential_type=credential_type,
            private_key=private_key_pem,
            managed_private_key=managed_private_key,
        )
        if certificate is not None:
            PrimaryCredentialCertificate.objects.create(
                certificate=certificate, credential=credential_model, is_primary=True
            )
        return credential_model

    @classmethod
    @transaction.atomic
    def save_managed_key_credential(
        cls,
        *,
        certificate: x509.Certificate,
        certificate_chain: list[x509.Certificate],
        credential_type: CredentialModel.CredentialTypeChoice,
        managed_key: CryptoManagedKeyModel,
    ) -> CredentialModel:
        """Store a credential whose private key is owned by the configured crypto backend."""
        certificate_model = CertificateModel.save_certificate(certificate)
        credential_model = cls._create_credential_model(
            certificate_model,
            credential_type,
            private_key_pem='',
            managed_private_key=managed_key,
        )
        cls._save_additional_certificates(credential_model, list(reversed(certificate_chain)))
        return credential_model

    @classmethod
    @transaction.atomic
    def save_managed_private_key_credential(
        cls,
        *,
        credential_type: CredentialModel.CredentialTypeChoice,
        managed_key: CryptoManagedKeyModel,
    ) -> CredentialModel:
        """Store a credential that has a backend-managed private key but no certificate yet."""
        return cls._create_credential_model(
            certificate=None,
            credential_type=credential_type,
            private_key_pem='',
            managed_private_key=managed_key,
        )

    @staticmethod
    def _save_additional_certificates(
        credential_model: CredentialModel, additional_certificates: list[x509.Certificate]
    ) -> None:
        """Saves additional certificates in the certificate chain."""
        if credential_model.certificate is None:
            return
        primary_cert = credential_model.certificate_or_error
        for order, certificate in enumerate(additional_certificates):
            certificate_model = CertificateModel.save_certificate(certificate)
            CertificateChainOrderModel.objects.create(
                certificate=certificate_model,
                credential=credential_model,
                order=order,
                primary_certificate=primary_cert,
            )

    @classmethod
    @transaction.atomic
    def save_keyless_credential(
        cls,
        certificate: x509.Certificate,
        certificate_chain: list[x509.Certificate],
        credential_type: CredentialModel.CredentialTypeChoice,
    ) -> CredentialModel:
        """Stores a credential without a private key."""
        certificate_model = CertificateModel.save_certificate(certificate)

        credential_model = cls.objects.create(
            certificate=certificate_model, credential_type=credential_type, private_key=''
        )

        PrimaryCredentialCertificate.objects.create(
            certificate=certificate_model, credential=credential_model, is_primary=True
        )

        primary_cert = credential_model.certificate_or_error

        for order, certificate_in_chain in enumerate(certificate_chain):
            certificate_model = CertificateModel.save_certificate(certificate_in_chain)
            CertificateChainOrderModel.objects.create(
                certificate=certificate_model,
                credential=credential_model,
                order=order,
                primary_certificate=primary_cert,
            )

        return credential_model

    @transaction.atomic
    def update_keyless_credential(
        self,
        certificate: x509.Certificate,
        certificate_chain: list[x509.Certificate],
    ) -> None:
        """Updates the primary certificate and certificate chain of the credential.

        Previous certificates are kept as part of the credential.
        """
        certificate_model = CertificateModel.save_certificate(certificate)
        self.certificate = certificate_model

        _, _ = PrimaryCredentialCertificate.objects.get_or_create(
            certificate=certificate_model, credential=self, is_primary=True
        )

        certificate_chain.reverse()
        for order, certificate_in_chain in enumerate(certificate_chain):
            certificate_model = CertificateModel.save_certificate(certificate_in_chain)
            _, _ = CertificateChainOrderModel.objects.get_or_create(
                certificate=certificate_model, credential=self, order=order, primary_certificate=self.certificate
            )

        self.save()

    def pre_delete(self) -> None:
        """Deletes related models, only allow deletion if there are no more active certificates."""
        # only allow deletion if all certificates are either expired or revoked
        qs = self.certificates.all()
        if self.certificate is None:
            if qs.exists():
                exc_msg = f'Cannot delete credential {self.pk} with certificates but no primary certificate.'
                raise ValidationError(exc_msg)
            return  # Nothing to check
        if self.certificate not in qs:
            exc_msg = f'Primary certificate not in certificate list of credential {self.pk}.'
            raise ValidationError(exc_msg)
        # Issued credentials must be revoked before deletion, not a requirement for CA credentials
        if self.credential_type == CredentialModel.CredentialTypeChoice.ISSUED_CREDENTIAL:
            for cert in qs:
                if cert.certificate_status in [
                    CertificateModel.CertificateStatus.OK,
                    CertificateModel.CertificateStatus.NOT_YET_VALID,
                ]:
                    exc_msg = f'Cannot delete credential {self} because it still has active certificates.'
                    self.logger.error(exc_msg)
                    raise ValidationError(exc_msg)
        self.certificates.clear()
        # CertificateChainOrderModel is deleted via CASCADE

    @transaction.atomic
    def force_delete(self) -> tuple[int, dict[str, int]]:
        """Delete the credential without running ``pre_delete`` and then delete its certificates."""
        certificates_to_delete: list[CertificateModel] = [
            chain_entry.certificate for chain_entry in self.ordered_certificate_chain_queryset.order_by('-order')
        ]
        if self.certificate is not None:
            certificates_to_delete.append(self.certificate)

        count = models.Model.delete(self)
        deleted_certificate_pks: set[int] = set()
        for certificate in certificates_to_delete:
            if certificate.pk in deleted_certificate_pks:
                continue
            deleted_certificate_pks.add(certificate.pk)
            certificate_in_db = CertificateModel.objects.filter(pk=certificate.pk).first()
            if certificate_in_db is None:
                continue
            if self._certificate_has_remaining_protected_references(certificate_in_db):
                continue
            certificate_in_db.delete()
        return count

    @staticmethod
    def _certificate_has_remaining_protected_references(certificate: CertificateModel) -> bool:
        """Return whether the certificate is still referenced through protected relations."""
        return (
            certificate.credential_set.exists()
            or certificate.certificatechainordermodel_set.exists()
            or certificate.primary_certificate_set.exists()
            or certificate.keyless_cas.exists()
        )

    def get_private_key(self) -> PrivateKey:
        """Gets an abstraction of the credential private key.

        Note, for backend-managed keys, it will only be possible to use the key abstraction to sign and verify,
        but not to export the key in any way.

        Returns:
            PrivateKey: The credential private key abstraction.
        """
        if self.private_key:
            return PrivateKeySerializer.from_pem(self.private_key.encode()).as_crypto()

        if self.managed_private_key:
            managed_key = managed_private_key_for_ref(self.managed_private_key.to_managed_key_ref())
            if isinstance(managed_key, (ManagedRSAPrivateKey, ManagedECPrivateKey)):
                return managed_key
            if isinstance(managed_key, (mldsa.MLDSA44PrivateKey, mldsa.MLDSA65PrivateKey, mldsa.MLDSA87PrivateKey)):
                return managed_key
            err_msg = f'Unsupported managed private key type: {type(managed_key)!r}.'
            raise RuntimeError(err_msg)

        err_msg = 'Failed to get private key information.'
        raise RuntimeError(err_msg)

    def get_private_key_serializer(self) -> PrivateKeySerializer:
        """Gets a serializer of the credential private key.

        Returns:
            PrivateKeySerializer: The credential private key serializer.

        Raises:
            RuntimeError: If no private key information is available or managed TLS export is denied.
        """
        if self.private_key:
            return PrivateKeySerializer.from_pem(self.private_key.encode())

        if self.managed_private_key:
            try:
                if self.credential_type == self.CredentialTypeChoice.TRUSTPOINT_TLS_SERVER:
                    private_key_pem = TrustpointCryptoBackend().export_private_key_pkcs8(
                        self.managed_private_key.to_managed_key_ref()
                    )
                    return PrivateKeySerializer.from_pem(private_key_pem)
                managed_key = managed_private_key_for_ref(self.managed_private_key.to_managed_key_ref())
                return self._private_key_serializer_from_key(managed_key)
            except Exception as e:
                err_msg = f'Failed to get managed private key: {e}'
                raise RuntimeError(err_msg) from e

        err_msg = 'Failed to get private key information.'
        raise RuntimeError(err_msg)

    @staticmethod
    def _private_key_serializer_from_key(key: Any) -> PrivateKeySerializer:
        """Build a private-key serializer from a key object or managed key facade."""
        return PrivateKeySerializer(key)

    def get_certificate(self) -> x509.Certificate:
        """Gets the credential certificate as x509.Certificate instance.

        Returns:
            x509.Certificate: The credential certificate.
        """
        return self.get_certificate_serializer().as_crypto()

    def get_certificate_chain(self) -> list[x509.Certificate]:
        """Gets the credential certificate chain as a list of x509.Certificate instances.

        Returns:
            list[x509.Certificate]: The credential certificate chain as list of x509.Certificate instances.
        """
        return self.get_certificate_chain_serializer().as_crypto()

    def get_certificate_serializer(self) -> CertificateSerializer:
        """Gets the credential certificate as a CertificateSerializer instance.

        Returns:
            CertificateSerializer: The credential certificate.

        Raises:
            ValueError: If the certificate is not set.
        """
        if self.certificate is None:
            msg = 'Certificate is not set for this credential'
            raise ValueError(msg)
        return self.certificate.get_certificate_serializer()

    def get_certificate_chain_serializer(self) -> CertificateCollectionSerializer:
        """Gets the credential certificate chain as a CertificateCollectionSerializer instance.

        Returns:
            CertificateCollectionSerializer: The credential certificate chain.
        """
        certificate_chain_order_models = self.certificatechainordermodel_set.order_by('order')
        return CertificateCollectionSerializer(
            [
                certificate_chain_order_model.certificate.get_certificate_serializer().as_crypto()
                for certificate_chain_order_model in certificate_chain_order_models
            ]
        )

    def get_last_in_chain(self) -> CertificateModel | None:
        """Gets the root ca certificate model, if any."""
        last_certificate_in_chain = self.certificatechainordermodel_set.order_by('order').last()
        if last_certificate_in_chain is None:
            return self.certificate
        return last_certificate_in_chain.certificate

    def get_root_ca_certificate(self) -> x509.Certificate | None:
        """Gets the root CA certificate of the credential certificate chain."""
        root_ca_certificate_serializer = self.get_root_ca_certificate_serializer()
        if root_ca_certificate_serializer:
            return root_ca_certificate_serializer.as_crypto()
        return None

    def get_root_ca_certificate_serializer(self) -> CertificateSerializer | None:
        """Get the root CA certificate serializer or a self-signed main certificate."""
        last_certificate_in_chain = self.certificatechainordermodel_set.order_by('order').last()
        if last_certificate_in_chain is not None and last_certificate_in_chain.certificate.is_root_ca:
            return last_certificate_in_chain.certificate.get_certificate_serializer()

        if self.certificate is not None and self.certificate.is_self_signed:
            return self.get_certificate_serializer()
        return None

    def get_credential_serializer(self) -> CredentialSerializer:
        """Gets the serializer for this credential."""
        return CredentialSerializer(
            private_key=self.get_private_key(),
            certificate=self.get_certificate_serializer().as_crypto(),
            additional_certificates=self.get_certificate_chain_serializer().as_crypto(),
        )

    @property
    def signature_suite(self) -> oid.SignatureSuite:
        """Returns the signature suite used by the current credential primary certificate."""
        return oid.SignatureSuite.from_certificate(self.get_certificate_serializer().as_crypto())

    @property
    def public_key_info(self) -> oid.PublicKeyInfo:
        """Returns the PublicKeyInfo the current credential primary certificate."""
        return self.signature_suite.public_key_info

    @property
    def hash_algorithm(self) -> hashes.HashAlgorithm | None:
        """Returns the hash algorithm used by the current credential."""
        return self.get_certificate().signature_hash_algorithm

    def is_valid_issued_credential(self) -> tuple[bool, str]:
        """Determines if this issued credential is valid.

        This method performs the following checks:
          1. The credential must be of type ISSUED_CREDENTIAL.
          2. A primary certificate must exist.
          3. The certificate's status must be 'OK'.

        Returns:
            tuple[bool, str]: A tuple where:
                          - The first value is True if the credential meets all criteria, False otherwise.
                          - The second value is a reason string explaining why the credential is invalid.
        """
        if self.credential_type != CredentialModel.CredentialTypeChoice.ISSUED_CREDENTIAL:
            return False, 'Invalid credential type: Must be ISSUED_CREDENTIAL.'

        primary_cert = self.certificate
        if primary_cert is None:
            return False, 'Missing primary certificate.'

        if primary_cert.certificate_status != primary_cert.CertificateStatus.OK:
            return False, f'Invalid certificate status: {primary_cert.certificate_status} (Must be OK).'

        return True, 'Valid issued credential.'


class PrimaryCredentialCertificate(models.Model):
    """Model to store which certificate is the primary certificate of a credential.

    Used as through model for the many-to-many relationship between CredentialModel and CertificateModel.
    """

    credential = models.ForeignKey(CredentialModel, on_delete=models.CASCADE)
    certificate = models.ForeignKey(CertificateModel, on_delete=models.CASCADE)
    is_primary = models.BooleanField(default=False)

    def __repr__(self) -> str:
        """Returns a string representation of this PrimaryCredentialCertificate entry."""
        return (
            f'PrimaryCredentialCertificate(credential={self.credential}, '
            f'certificate={self.certificate}, '
            f'is_primary={self.is_primary})'
        )

    def __str__(self) -> str:
        """Returns a human-readable string that represents this PrimaryCredentialCertificate entry."""
        return self.__repr__()

    def save(self, *args: Any, **kwargs: Any) -> None:
        """If a new certificate is added to a credential, it is set to primary and all others to non-primary."""
        if not self.pk or self.is_primary:
            PrimaryCredentialCertificate.objects.filter(credential=self.credential).update(is_primary=False)

        self.is_primary = True
        super().save(*args, **kwargs)


class CertificateChainOrderModel(models.Model):
    """This Model is used to preserve the order of certificates in credential certificate chains."""

    certificate = models.ForeignKey(CertificateModel, on_delete=models.PROTECT, null=False, blank=False, editable=False)
    credential = models.ForeignKey(CredentialModel, on_delete=models.CASCADE, null=False, blank=False, editable=False)
    order = models.PositiveIntegerField(null=False, blank=False, editable=False)
    primary_certificate = models.ForeignKey(
        CertificateModel,
        on_delete=models.PROTECT,
        null=False,
        blank=False,
        editable=False,
        related_name='primary_certificate_set',
    )

    class Meta:
        """This Meta class add some configuration to the CertificateChainOrderModel.

        Sets the default ordering such that the field order is used.
        Restricts entries such that the tuple (credential, order) is unique.
        """

        ordering: ClassVar[list[str]] = ['order']
        constraints: ClassVar[list[models.BaseConstraint]] = [
            models.UniqueConstraint(
                fields=['credential', 'primary_certificate', 'order'],
                name='unique_group_order',
            )
        ]

    def __repr__(self) -> str:
        """Returns a string representation of this CertificateChainOrderModel entry."""
        return (
            f'CertificateChainOrderModel(credential={self.credential}, '
            f'certificate={self.certificate}, '
            f'primary_certificate={self.primary_certificate}, '
            f'order={self.order})'
        )

    def __str__(self) -> str:
        """Returns a human-readable string that represents this CertificateChainOrderModel entry.

        Returns:
            str: Human-readable string that represents this CertificateChainOrderModel entry.
        """
        return self.__repr__()

    # TODO(AlexHx8472): Validate certificate chain!  # noqa: FIX002
    def save(self, *args: Any, **kwargs: Any) -> None:
        """Stores a CertificateChainOrderModel in the database.

        This is only possible if the order takes the next available value. That is, e.g. if the corresponding
        credential certificate chain has already two certificates stored with order 0 and 1, then the next
        entry to be stored must have order 2.

        Args:
            *args: Positional arguments, passed to super().save()
            **kwargs: Keyword arguments, passed to super().save()

        Returns:
            None

        Raises:
            ValueError:
                If the CertificateChainOrderModel entry to be stored does not have the correct order.
        """
        max_order = self._get_max_order()

        if self.order != max_order + 1:
            err_msg = f'Cannot add Membership with order {self.order}. Expected {max_order + 1}.'
            raise ValidationError(err_msg)
        super().save(*args, **kwargs)

    def delete(self, *args: Any, **kwargs: Any) -> tuple[int, dict[str, int]]:
        """Tries to delete the CertificateChainOrderModel entry.

        A CertificateChainOrderModel entry can only be deleted if it has the highest order in the
        corresponding credential certificate chain.

        Args:
            *args: Positional arguments, passed to super().delete()
            **kwargs: Keyword arguments, passed to super().delete()

        Returns:
            tuple[int, dict[str, int]] (returned by parent)

        Raises:
            ValueError:
                If the CertificateChainOrderModel entry does not have the highest order in the corresponding
                credential certificate chain.
        """
        max_order = self._get_max_order()

        if self.order != max_order:
            err_msg = (
                f'Only the Membership with the highest order ({max_order}) '
                f'can be deleted. This Membership has order {self.order}.'
            )
            raise ValidationError(err_msg)

        return super().delete(*args, **kwargs)

    def _get_max_order(self) -> int:
        """Gets highest order of a certificate of a credential certificate chain.

        Returns:
            int: The highest order of a certificate of a credential certificate chain.
        """
        existing_orders = CertificateChainOrderModel.objects.filter(
            credential=self.credential, primary_certificate=self.primary_certificate
        ).values_list('order', flat=True)
        return max(existing_orders, default=-1)


class IDevIDReferenceModel(models.Model):
    """Model to store the string referencing an IDevID certificate.

    Obtained from the SAN of the DevOwnerID certificate.

    The ``idevid_ref`` field holds the raw ``dev-owner:`` URI embedded in the DevOwnerID SAN.
    ``dev_owner_id_certificate`` points to the :class:`~pki.models.certificate.CertificateModel`
    of the DevOwnerID certificate whose SAN contained this reference, so the details view can
    display the DevOwnerID certificate information without a fragile fingerprint-string lookup.
    """

    dev_owner_id = models.ForeignKey(
        'RemoteIssuedCredentialModel', related_name='idevid_ref_set', on_delete=models.CASCADE
    )
    idevid_ref = models.CharField(max_length=255, verbose_name=_('IDevID Identifier'))
    dev_owner_id_certificate = models.ForeignKey(
        CertificateModel,
        verbose_name=_('DevOwnerID Certificate'),
        on_delete=models.SET_NULL,
        related_name='idevid_refs',
        null=True,
        blank=True,
        help_text=_('The DevOwnerID certificate whose SAN contained this IDevID reference.'),
    )

    def __str__(self) -> str:
        """Returns a human-readable string that represents this IDevIDRefSanModel entry."""
        return f'{self.dev_owner_id.common_name} - {self.idevid_ref}'

    @property
    def idevid_subject_serial_number(self) -> str:
        """Returns the IDevID Subject Serial Number from the SAN of the DevOwnerID certificate.

        The stored ``idevid_ref`` format is ``dev-owner:<subj_sn>.<x509_sn>.<sha256_fingerprint>``.
        This property strips the ``dev-owner:`` scheme prefix and returns the first segment.
        """
        if not self.idevid_ref.startswith('dev-owner:cert:'):
            return ''
        try:
            # Remove 'dev-owner:cert:' prefix before splitting
            return self.idevid_ref.removeprefix('dev-owner:cert:').split('_')[0]
        except IndexError:
            return ''

    @property
    def idevid_san_uri(self) -> str:
        """Returns the IDevID SAN URI reference from the DevOwnerID certificate.

        Second dot-separated segment after stripping the ``dev-owner:uri:`` prefix.
        """
        if not self.idevid_ref.startswith('dev-owner:uri:'):
            return ''
        return self.idevid_ref.removeprefix('dev-owner:uri:')

    @property
    def idevid_subj_sn_or_san_uri(self) -> str:
        """Returns the IDevID Subject Serial Number or SAN URI from the SAN of the DevOwnerID certificate.

        This property returns the Subject Serial Number if the stored reference
        starts with ``dev-owner:cert:``, and returns the SAN URI if it starts with ``dev-owner:uri:``.
        """
        return self.idevid_subject_serial_number or self.idevid_san_uri

    @property
    def idevid_sha256_fingerprint(self) -> str:
        """Returns the IDevID SHA256 Fingerprint from the SAN of the DevOwnerID certificate.

        Third dot-separated segment after stripping the ``dev-owner:`` prefix.
        """
        if not self.idevid_ref.startswith('dev-owner:cert:'):
            return ''
        try:
            return self.idevid_ref.removeprefix('dev-owner:cert:').split('_')[1]
        except IndexError:
            return ''

    @property
    def domain_ca_sha256_fingerprint(self) -> str:
        """Return the pinned domain CA SHA256 fingerprint from a ``dev-owner:ca:<sha256_hex>`` reference."""
        if not self.idevid_ref.startswith('dev-owner:ca:'):
            return ''
        return self.idevid_ref.removeprefix('dev-owner:ca:')

    @property
    def sha256_fingerprint_display(self) -> str:
        """Returns the SHA256 Fingerprint for display purposes.

        This property returns the SHA256 Fingerprint of the IDevID if available, otherwise that of the domain CA.
        """
        if fingerprint := self.idevid_sha256_fingerprint:
            return fingerprint
        if domain_fp := self.domain_ca_sha256_fingerprint:
            return f'Pinned CA: {domain_fp}'
        return ''
