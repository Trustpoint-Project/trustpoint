"""Module that contains the CrlModel."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, ClassVar

from cryptography import x509
from django.core.exceptions import ValidationError
from django.db import models
from django.utils import timezone
from django.utils.translation import gettext_lazy as _

from trustpoint.logger import LoggerMixin
from util.db import CustomDeleteActionModel

if TYPE_CHECKING:
    import datetime

    from pki.models import CaModel


class CrlModel(LoggerMixin, CustomDeleteActionModel):
    """Certificate Revocation List Model.

    This model stores CRLs for CAs (both issuing and non-issuing).
    Multiple CRLs can exist for a single CA to track CRL history.
    """

    ca = models.ForeignKey(
        'pki.CaModel',
        related_name='crls',
        on_delete=models.CASCADE,
        verbose_name=_('Certificate Authority'),
        help_text=_('The CA that issued this CRL')
    )

    crl_pem = models.TextField(
        verbose_name=_('CRL in PEM format'),
        help_text=_('The Certificate Revocation List in PEM format')
    )

    crl_number = models.PositiveBigIntegerField(
        verbose_name=_('CRL Number'),
        help_text=_('The CRL number from the CRL extension'),
        null=True,
        blank=True,
    )

    this_update = models.DateTimeField(
        verbose_name=_('This Update'),
        help_text=_('The thisUpdate field from the CRL')
    )

    next_update = models.DateTimeField(
        verbose_name=_('Next Update'),
        null=True,
        blank=True,
        help_text=_('The nextUpdate field from the CRL')
    )

    validity_period = models.DurationField(
        verbose_name=_('Validity Period'),
        null=True,
        blank=True,
        help_text=_('The duration between this_update and next_update (how long this CRL is valid)')
    )

    is_active = models.BooleanField(
        _('Active'),
        default=True,
        help_text=_('Whether this is the current active CRL for the CA')
    )

    created_at = models.DateTimeField(
        verbose_name=_('Created'),
        auto_now_add=True
    )

    updated_at = models.DateTimeField(
        verbose_name=_('Updated'),
        auto_now=True
    )

    class Meta:
        """Meta options for CrlModel."""

        verbose_name = _('Certificate Revocation List')
        verbose_name_plural = _('Certificate Revocation Lists')
        ordering: ClassVar[list[str]] = ['-this_update']
        unique_together: ClassVar[list[list[str]]] = [['ca', 'crl_number']]
        indexes: ClassVar[list[models.Index]] = [
            models.Index(fields=['ca', '-this_update']),
            models.Index(fields=['ca', 'is_active']),
        ]

    def __str__(self) -> str:
        """Returns a human-readable string representation.

        Returns:
            str: Human-readable string representation.
        """
        if self.crl_number is not None:
            return f'CRL #{self.crl_number} for {self.ca.unique_name}'
        return f'CRL for {self.ca.unique_name} (no number)'

    def __repr__(self) -> str:
        """Returns a string representation of the instance."""
        return f'CrlModel(id={self.pk}, ca={self.ca_id}, crl_number={self.crl_number})'

    @classmethod
    def create_from_pem(
        cls,
        ca: CaModel,
        crl_pem: str,
        *,
        set_active: bool = True,
        next_update_delta: datetime.timedelta | None = None,
    ) -> CrlModel:
        """Creates a new CRL from PEM data.

        Args:
            ca: The CA that issued this CRL.
            crl_pem: The CRL in PEM format.
            set_active: If True, deactivates other CRLs for this CA and sets this as active.
            next_update_delta: Optional timedelta to override the CRL's nextUpdate field.
                              If provided, sets nextUpdate to thisUpdate + delta.

        Returns:
            CrlModel: The newly created CRL model.

        Raises:
            ValidationError: If the CRL is invalid or doesn't match the CA.
        """
        try:
            crl = x509.load_pem_x509_crl(crl_pem.encode())
        except Exception as e:
            raise ValidationError(_('Failed to parse the CRL. It may be corrupted or invalid.')) from e

        ca_cert = ca.ca_certificate_model.get_certificate_serializer().as_crypto()
        if crl.issuer != ca_cert.subject:
            raise ValidationError(
                _(
                    'The CRL issuer does not match the CA subject. '
                    'This CRL was not issued by this CA.'
                )
            )

        crl_number = None
        try:
            crl_number_ext = crl.extensions.get_extension_for_class(x509.CRLNumber)
            crl_number = crl_number_ext.value.crl_number
        except x509.ExtensionNotFound:
            pass

        this_update = crl.last_update_utc
        next_update = crl.next_update_utc

        if next_update_delta is not None:
            next_update = this_update + next_update_delta

        validity_period = None
        if next_update is not None:
            validity_period = next_update - this_update

        crl_model = cls(
            ca=ca,
            crl_pem=crl_pem,
            crl_number=crl_number,
            this_update=this_update,
            next_update=next_update,
            validity_period=validity_period,
            is_active=set_active,
        )
        crl_model.save()

        if set_active:
            cls.objects.filter(ca=ca, is_active=True).exclude(pk=crl_model.pk).update(is_active=False)

        return crl_model

    def get_crl_as_crypto(self) -> x509.CertificateRevocationList:
        """Returns the CRL as a cryptography CertificateRevocationList object.

        Returns:
            x509.CertificateRevocationList: The CRL.

        Raises:
            ValidationError: If the CRL cannot be parsed.
        """
        try:
            return x509.load_pem_x509_crl(self.crl_pem.encode())
        except Exception as e:
            self.logger.exception('Failed to load CRL for CA %s', self.ca.unique_name)
            raise ValidationError(_('Failed to parse the stored CRL.')) from e

    def get_revoked_serial_numbers(self) -> set[int]:
        """Returns a set of revoked certificate serial numbers.

        Returns:
            set[int]: Set of revoked serial numbers.
        """
        crl = self.get_crl_as_crypto()
        return {revoked_cert.serial_number for revoked_cert in crl}

    def is_certificate_revoked(self, serial_number: int) -> bool:
        """Checks if a certificate with the given serial number is revoked.

        Args:
            serial_number: The certificate serial number to check.

        Returns:
            bool: True if the certificate is revoked, False otherwise.
        """
        return serial_number in self.get_revoked_serial_numbers()

    def is_expired(self) -> bool:
        """Checks if this CRL has expired based on nextUpdate.

        Returns:
            bool: True if the CRL has expired, False otherwise.
        """
        if self.next_update is None:
            return False
        return timezone.now() > self.next_update

    def get_validity_hours(self) -> float | None:
        """Returns the validity period in hours.

        Returns:
            float | None: The validity period in hours, or None if not set.
        """
        if self.validity_period is None:
            return None
        return self.validity_period.total_seconds() / 3600

    def save(self, *args: Any, **kwargs: Any) -> None:
        """Override save to validate before saving."""
        # Ensure only one active CRL per CA
        if self.is_active:
            CrlModel.objects.filter(ca=self.ca, is_active=True).exclude(pk=self.pk).update(is_active=False)
        super().save(*args, **kwargs)

    def pre_delete(self) -> None:
        """Called before deleting the model."""
        self.logger.info('Deleting CRL for CA %s (CRL Number: %s)', self.ca.unique_name, self.crl_number)
