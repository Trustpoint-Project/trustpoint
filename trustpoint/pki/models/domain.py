"""Module that contains the DomainModel."""
from __future__ import annotations

from util.field import UniqueNameValidator
from django.core.exceptions import ValidationError
from django.db import models
from django.utils.translation import gettext_lazy as _
from trustpoint_core import oid

from . import IssuingCaModel

__all__ = [
    'DomainModel'
]


class DomainModel(models.Model):
    """Domain Model."""

    unique_name = models.CharField(
        _('Domain Name'),
        max_length=100,
        unique=True,
        validators=[UniqueNameValidator()])

    issuing_ca = models.ForeignKey(
        IssuingCaModel,
        on_delete=models.CASCADE,
        blank=False,
        null=True,
        verbose_name=_('Issuing CA'),
        related_name='domains',
    )

    is_active = models.BooleanField(
        _('Active'),
        default=True,
    )

    created_at = models.DateTimeField(verbose_name=_('Created'), auto_now_add=True)
    updated_at = models.DateTimeField(verbose_name=_('Updated'), auto_now=True)

    auto_create_new_device = models.BooleanField(
        _('Auto-create New Device'),
        default=False,
        help_text=_(
            "Automatically create a new device if no device with the same serial number exists in the database."
        )
    )

    allow_username_password_registration = models.BooleanField(
        _('Allow username:password Registration'),
        default=False,
        help_text=_("New devices can be added with a username and password.")
    )

    allow_idevid_registration = models.BooleanField(
        _('Allow IDevID Registration'),
        default=False,
        help_text=_("Allow registration of a new device using the IDevID of the Device.")
    )

    domain_credential_auth = models.BooleanField(
        _('Require a Domain Credential for Authentication'),
        default=True,
        help_text=_("The EST server requires a domain credential issued by the domain Issuing CA for authenitcation.")
    )

    username_password_auth = models.BooleanField(
        _('Require username:password for Authentication'),
        default=False,
        help_text=_("The EST server requires username and password for authentication.")
    )

    allow_app_certs_without_domain = models.BooleanField(
        _('Allow Application Certificates without Domain Credential'),
        default=False,
        help_text=_("Allow issuance of application certificates without a domain credential.")
    )

    def __repr(self) -> str:
        return f'DomainModel(unique_name={self.unique_name})'

    def __str__(self) -> str:
        """Human-readable representation of the Domain model instance.

        Returns:
            str:
                Human-readable representation of the EndpointProfile model instance.
        """
        return self.unique_name

    @property
    def signature_suite(self) -> oid.SignatureSuite:
        return oid.SignatureSuite.from_certificate(self.issuing_ca.credential.get_certificate_serializer().as_crypto())

    @property
    def public_key_info(self) -> oid.PublicKeyInfo:
        return self.signature_suite.public_key_info

    def save(self, *args: tuple, **kwargs: dict) -> None:
        """Save the Domain model instance."""
        self.clean()  # Ensure validation before saving
        super().save(*args, **kwargs)

    def clean(self) -> None:
        """Validate that the issuing CA is not an auto-generated root CA."""
        if self.issuing_ca and self.issuing_ca.issuing_ca_type == IssuingCaModel.IssuingCaTypeChoice.AUTOGEN_ROOT:
            exc_msg = 'The issuing CA associated with the domain cannot be an auto-generated root CA.'
            raise ValidationError(exc_msg)