"""This module defines models for managing trustpoints, including server credentials and truststores."""

from __future__ import annotations

from typing import Any

from django.db import models
from django.utils.translation import gettext_lazy as _
from django_stubs_ext.db.models import TypedModelMeta
from trustpoint_core.serializer import CertificateCollectionSerializer
from util.field import UniqueNameValidator

from .certificate import CertificateModel
from .credential import CredentialModel

__all__ = [
    'ActiveTrustpointTlsServerCredentialModel',
    'TruststoreModel',
    'TruststoreOrderModel',
]


class ActiveTrustpointTlsServerCredentialModel(models.Model):
    """Represents the currently active TLS server credential.

    This model tracks the active server credential, ensuring that it is always
    up-to-date and linked to a specific `CredentialModel` instance.
    """

    credential = models.ForeignKey(CredentialModel, on_delete=models.CASCADE, blank=True, null=True)

    class Meta(TypedModelMeta):
        """Meta class configuration."""

    def __str__(self) -> str:
        """Returns a human-readable string representation of the active credential.

        Returns:
            str: Description of the active TLS server credential.
        """
        return f'Active TLS Credential: {self.credential.id if self.credential else "None"}'

    def save(self, *args: Any, **kwargs: Any) -> None:
        """Ensures the model instance always has an ID of 1 to enforce singleton-like behavior.

        Returns:
            None
        """
        self.id = 1
        super().save(*args, **kwargs)


class TruststoreModel(models.Model):
    """Represents a truststore, which is a collection of certificates used for specific purposes.

    This model allows organizing certificates into a logical grouping for specific
    intended usages such as `IDevID`, `TLS`, or `Generic`. Each truststore is identified
    by a unique name and supports operations like retrieving the number of certificates
    or serializing its content.
    """

    class IntendedUsage(models.IntegerChoices):
        """Intended Usage of the Truststore."""

        IDEVID = 0, _('IDevID')
        TLS = 1, _('TLS')
        GENERIC = 2, _('Generic')
        DEVICE_OWNER_ID = 3, _('Device Owner ID')

    unique_name = models.CharField(
        verbose_name=_('Unique Name'), max_length=100, validators=[UniqueNameValidator()], unique=True
    )

    certificates = models.ManyToManyField(
        to=CertificateModel, verbose_name=_('Truststore certificates'), through='TruststoreOrderModel'
    )

    intended_usage = models.IntegerField(
        verbose_name=_('Intended Usage'), choices=IntendedUsage, null=False, blank=False
    )

    created_at = models.DateTimeField(verbose_name=_('Created-At'), auto_now_add=True)

    class Meta(TypedModelMeta):
        """Meta class configuration."""

    def __str__(self) -> str:
        """Returns a human-readable string representation of the TruststoreModel."""
        return self.unique_name

    def save(self, **kwargs: Any) -> None:
        """Ensures the model is valid before saving."""
        self.full_clean()
        super().save(**kwargs)

    @property
    def number_of_certificates(self) -> int:
        """Returns the number of certificates in the truststore."""
        return len(self.certificates.all())

    def get_certificate_collection_serializer(self) -> CertificateCollectionSerializer:
        """Returns a serializer for all certificates in the truststore.

        This method gathers all the certificates associated with the truststore,
        serializes them using `CertificateCollectionSerializer`, and returns
        the serialized result.

        Returns:
            The serialized representation of the certificates.
        """
        return CertificateCollectionSerializer(
            [
                cert.certificate.get_certificate_serializer().as_crypto()
                for cert in self.truststoreordermodel_set.order_by('order')
            ]
        )


class TruststoreOrderModel(models.Model):
    """Represents the order of certificates in a truststore."""

    order = models.PositiveSmallIntegerField(verbose_name=_('Trust Store Certificate Index (Order)'), editable=False)
    certificate = models.ForeignKey(
        CertificateModel, on_delete=models.CASCADE, editable=False, related_name='trust_store_components'
    )
    trust_store = models.ForeignKey(TruststoreModel, on_delete=models.CASCADE, editable=False)

    class Meta(TypedModelMeta):
        """Meta class configuration."""

        unique_together = ('order', 'trust_store')

    def __str__(self) -> str:
        """Returns a human-readable string representation of the TruststoreOrderModel."""
        return f'Truststore Order {self.order} for Truststore {self.trust_store.unique_name}'
