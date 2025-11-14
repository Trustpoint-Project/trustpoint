"""Module that contains the DomainModel."""

from __future__ import annotations

from typing import TYPE_CHECKING

from django.core.exceptions import ValidationError
from django.db import models
from django.utils.translation import gettext_lazy as _
from trustpoint_core import oid
from util.field import UniqueNameValidator

if TYPE_CHECKING:
    from typing import Any

    from cert_profile import CertificateProfileModel

from . import IssuingCaModel

__all__ = ['DomainModel']


class DomainModel(models.Model):
    """Domain Model."""

    unique_name = models.CharField(_('Domain Name'), max_length=100, unique=True, validators=[UniqueNameValidator()])

    issuing_ca = models.ForeignKey(
        IssuingCaModel,
        on_delete=models.PROTECT,
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

    def __repr__(self) -> str:
        """Machine-readable representation of the Domain model instance.

        Returns:
            str:
                Machine-readable representation of the Domain model model instance.
        """
        return f'DomainModel(unique_name={self.unique_name})'

    def __str__(self) -> str:
        """Human-readable representation of the Domain model instance.

        Returns:
            str:
                Human-readable representation of the Domain model model instance.
        """
        return self.unique_name

    def save(self, **kwargs: Any) -> None:
        """Save the Domain model instance."""
        self.clean()
        super().save(**kwargs)

    @property
    def signature_suite(self) -> oid.SignatureSuite:
        """Get the signature suite for the domain (based on its Issuing CA)."""
        return oid.SignatureSuite.from_certificate(
            self.get_issuing_ca_or_value_error().credential.get_certificate_serializer().as_crypto())

    @property
    def public_key_info(self) -> oid.PublicKeyInfo:
        """Get the public key info for the domain (based on its Issuing CA)."""
        return self.signature_suite.public_key_info

    def clean(self) -> None:
        """Validate that the issuing CA is not an auto-generated root CA."""
        if self.issuing_ca and self.issuing_ca.issuing_ca_type == IssuingCaModel.IssuingCaTypeChoice.AUTOGEN_ROOT:
            exc_msg = 'The issuing CA associated with the domain cannot be an auto-generated root CA.'
            raise ValidationError(exc_msg)

    def get_issuing_ca_or_value_error(self) -> IssuingCaModel:
        """Gets the corresponding Issuing CA.

        Returns:
            The corresponding Issuing CA.

        Raises:
            ValueError: If no Issuing CA is set.
        """
        if not self.issuing_ca:
            err_msg = f'Domain {self.unique_name} does not have a corresponding Issuing CA configured.'
            raise ValueError(err_msg)
        return self.issuing_ca

    def get_allowed_cert_profile_names(self) -> set[str]:
        """Gets the set of allowed certificate profile names for this domain.

        Returns:
            Set of allowed certificate profile names.
        """
        allowed_profiles = self.certificate_profiles.all()
        allowed_profile_names = {profile.certificate_profile.unique_name for profile in allowed_profiles}
        allowed_profile_names.update(profile.alias for profile in allowed_profiles if profile.alias)
        return allowed_profile_names

    def get_allowed_cert_profile(self, cert_profile_str: str) -> CertificateProfileModel:
        """Gets the requested certificate profile if it is allowed for this domain. Else, raises a ValueError.

        Args:
            cert_profile_str: The name of the certificate profile to check.

        Returns:
            The requested CertificateProfileModel (if allowed).
        """
        # try query from alias first
        profile_qs = self.certificate_profiles.filter(alias=cert_profile_str)
        if not profile_qs.exists():
            # fall back to unique_name
            profile_qs = self.certificate_profiles.filter(
                certificate_profile__unique_name=cert_profile_str
            )
        if not profile_qs.exists():
            err_msg = f'Certificate profile "{cert_profile_str}" does not exist or not allowed in domain.'
            raise ValueError(err_msg)
        return profile_qs.first().certificate_profile  # type: ignore[union-attr]
