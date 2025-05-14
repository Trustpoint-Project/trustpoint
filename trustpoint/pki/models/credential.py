"""Module that contains the CredentialModel."""

from __future__ import annotations

from typing import TYPE_CHECKING

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
from util.db import CustomDeleteActionModel

from pki.models import CertificateModel
from trustpoint.views.base import LoggerMixin

if TYPE_CHECKING:
    from typing import Any, ClassVar

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from django.db.models import QuerySet
    from trustpoint_core.key_types import PrivateKey


__all__ = ['CertificateChainOrderModel', 'CredentialAlreadyExistsError', 'CredentialModel']


class CredentialAlreadyExistsError(ValidationError):
    """The CredentialAlreadyExistsError is raised if a credential already exists in the database."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """Initializes the CredentialAlreadyExistsError with a default message."""
        super().__init__(_('Credential already exists.'), *args, **kwargs)


class CredentialModel(LoggerMixin, CustomDeleteActionModel):
    """The CredentialModel that holds all local credentials used by the Trustpoint.

    This model holds both local unprotected credentials, for which the keys and certificates are stored
    in the DB, but also credentials that are stored within an HSM or TPM utilizing PKCS#11.

    PKCS#11 credentials are not yet supported.
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

    credential_type = models.IntegerField(verbose_name=_('Credential Type'), choices=CredentialTypeChoice)
    private_key = models.CharField(verbose_name='Private key (PEM)', max_length=65536, default='', blank=True)

    certificate = models.ForeignKey(
        CertificateModel, on_delete=models.PROTECT, related_name='credential_set', blank=False
    )

    certificates = models.ManyToManyField(
        CertificateModel, through='PrimaryCredentialCertificate', blank=False, related_name='credential'
    )
    certificate_chain = models.ManyToManyField(
        CertificateModel, blank=True,
        through='CertificateChainOrderModel',
        through_fields=('credential', 'certificate'),
        related_name='credential_certificate_chains'
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
        qs = self.primarycredentialcertificate_set.filter(is_primary=True)
        if qs.count() > 1:
            exc_msg = 'A credential can only have one primary certificate.'
            raise ValidationError(exc_msg)

        if qs.get().certificate != self.certificate:
            exc_msg = ('The ForeignKey certificate must be identical to the one '
                       'marked primary in the primarycredentialcertificate_set.')

            raise ValidationError(exc_msg)

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
        """This method will store a credential that is expected to be normalized..

        Args:
            normalized_credential_serializer: The normalized credential serializer to store in the database.
            credential_type: The credential type to set.

        Returns:
            CredentialModel: The stored credential model.
        """
        certificate = CertificateModel.save_certificate(normalized_credential_serializer.certificate)
        # TODO(AlexHx8472): Verify that the credential is valid in respect to the credential_type!!!

        credential_model = cls.objects.create(
            certificate=certificate,
            credential_type=credential_type,
            private_key=normalized_credential_serializer.get_private_key_serializer().as_pkcs8_pem().decode(),
        )

        PrimaryCredentialCertificate.objects.create(
            certificate=certificate, credential=credential_model, is_primary=True
        )

        for order, certificate in enumerate(normalized_credential_serializer.additional_certificates):
            certificate_model = CertificateModel.save_certificate(certificate)
            CertificateChainOrderModel.objects.create(
                certificate=certificate_model,
                credential=credential_model,
                order=order,
                primary_certificate=credential_model.certificate
            )

        return credential_model

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

        for order, certificate_in_chain in enumerate(certificate_chain):
            certificate_model = CertificateModel.save_certificate(certificate_in_chain)
            CertificateChainOrderModel.objects.create(
                certificate=certificate_model,
                credential=credential_model,
                order=order,
                primary_certificate=credential_model.certificate
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

        # Consider adding private key update logic here if needed

        _, _ = PrimaryCredentialCertificate.objects.get_or_create(
            certificate=certificate_model, credential=self, is_primary=True
        )

        # Store the complete chain for each new primary certificate
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
        if self.certificate not in qs:
            exc_msg = f'Primary certificate not in certificate list of credential {self.pk}.'
            raise ValidationError(exc_msg)
        # Issued credentials must be revoked before deletion, not a requirement for CA credentials
        if self.credential_type == CredentialModel.CredentialTypeChoice.ISSUED_CREDENTIAL:
            for cert in qs:
                if (cert.certificate_status in
                    [CertificateModel.CertificateStatus.OK, CertificateModel.CertificateStatus.NOT_YET_VALID]):
                    exc_msg = f'Cannot delete credential {self} because it still has active certificates.'
                    self.logger.error(exc_msg)
                    raise ValidationError(exc_msg)
        self.certificates.clear()
        self.certificate = None
        # CertificateChainOrderModel is deleted via CASCADE

    def get_private_key(self) -> PrivateKey:
        """Gets an abstraction of the credential private key.

        Note, in the case of keys stored in an HSM or TPM using PKCS#11, it will only be possible to use the
        key abstraction to sign and verify, but not to export the key in any way.

        Returns:
            PrivateKey: The credential private key abstraction.
        """
        if self.private_key:
            return PrivateKeySerializer.from_pem(self.private_key.encode()).as_crypto()

        err_msg = 'Failed to get private key information.'
        raise RuntimeError(err_msg)

    def get_private_key_serializer(self) -> PrivateKeySerializer:
        """Gets a serializer of the credential private key.

        Returns:
            PrivateKey: The credential private key abstraction.
        """
        if self.private_key:
            return PrivateKeySerializer.from_pem(self.private_key.encode())

        err_msg = 'Failed to get private key information.'
        raise RuntimeError(err_msg)

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
        """
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

    def get_root_ca_certificate(self) -> None | x509.Certificate:
        """Gets the root CA certificate of the credential certificate chain."""
        root_ca_certificate_serializer = self.get_root_ca_certificate_serializer()
        if root_ca_certificate_serializer:
            return root_ca_certificate_serializer.as_crypto()
        return None

    def get_root_ca_certificate_serializer(self) -> None | CertificateSerializer:
        """Gets the root CA certificate serializer."""
        last_certificate_in_chain = self.certificatechainordermodel_set.order_by('order').last()
        if last_certificate_in_chain.certificate.is_root_ca:
            return last_certificate_in_chain.certificate.get_certificate_serializer()
        return None

    def get_credential_serializer(self) -> CredentialSerializer:
        """Gets the serializer for this credential."""
        return CredentialSerializer(
            private_key=self.get_private_key_serializer().as_crypto(),
            certificate=self.get_certificate_serializer().as_crypto(),
            additional_certificates=self.get_certificate_chain_serializer().as_crypto()
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
    def hash_algorithm(self) -> hashes.HashAlgorithm  | None:
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
    certificate = models.OneToOneField(CertificateModel, on_delete=models.CASCADE)
    is_primary = models.BooleanField(default=False)

    objects: models.Manager[PrimaryCredentialCertificate]

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
        CertificateModel, on_delete=models.PROTECT, null=False, blank=False, editable=False,
        related_name = 'primary_certificate_set'
    )

    objects: models.Manager[CertificateChainOrderModel]

    class Meta:
        """This Meta class add some configuration to the CertificateChainOrderModel.

        Sets the default ordering such that the field order is used.
        Restricts entries such that the tuple (credential, order) is unique.
        """

        ordering: ClassVar = ['order']
        constraints: ClassVar = [models.UniqueConstraint(
            fields=['credential', 'primary_certificate', 'order'], name='unique_group_order'
        )]

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

    # TODO(AlexHx8472): Validate certificate chain!
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
        ).values_list(
            'order', flat=True
        )
        return max(existing_orders, default=-1)
