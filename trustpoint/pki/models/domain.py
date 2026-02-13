"""Module that contains the DomainModel."""

from __future__ import annotations

from typing import TYPE_CHECKING

from django.core.exceptions import ValidationError
from django.db import models, transaction
from django.db.models import Q
from django.utils.translation import gettext_lazy as _
from django_stubs_ext.db.models import TypedModelMeta
from trustpoint_core import oid

from util.field import UniqueNameValidator

if TYPE_CHECKING:
    from typing import Any, ClassVar

from . import CaModel
from .cert_profile import CertificateProfileModel

__all__ = ['DomainAllowedCertificateProfileModel', 'DomainModel']


class DomainModel(models.Model):
    """Domain Model."""

    unique_name = models.CharField(_('Domain Name'), max_length=100, unique=True, validators=[UniqueNameValidator()])

    issuing_ca = models.ForeignKey(
        CaModel,
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
        """Save the Domain model and add default certificate profiles."""
        self.clean()
        is_new_instance = not self.pk
        super().save(**kwargs)
        if is_new_instance:
            self._add_default_profiles()


    @property
    def signature_suite(self) -> oid.SignatureSuite | None:
        """Get the signature suite for the domain (based on its Issuing CA).

        Returns None if the issuing CA doesn't have a certificate yet.
        """
        issuing_ca = self.get_issuing_ca_or_value_error()
        if issuing_ca.credential and not issuing_ca.credential.certificate:
            return None
        try:
            return oid.SignatureSuite.from_certificate(issuing_ca.get_certificate())
        except ValueError:
            return None

    @property
    def public_key_info(self) -> oid.PublicKeyInfo | None:
        """Get the public key info for the domain (based on its Issuing CA).

        Returns None if the issuing CA doesn't have a certificate yet.
        """
        if self.signature_suite is None:
            return None
        return self.signature_suite.public_key_info

    def clean(self) -> None:
        """Validate that the issuing CA is not an auto-generated root CA."""
        if self.issuing_ca and self.issuing_ca.ca_type == CaModel.CaTypeChoice.AUTOGEN_ROOT:
            exc_msg = 'The issuing CA associated with the domain cannot be an auto-generated root CA.'
            raise ValidationError(exc_msg)

    def get_issuing_ca_or_value_error(self) -> CaModel:
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

    def get_allowed_cert_profiles(self) -> models.QuerySet[DomainAllowedCertificateProfileModel]:
        """Gets the allowed certificate profiles for this domain.

        Returns:
            QuerySet of allowed DomainAllowedCertificateProfileModel instances.
        """
        return self.certificate_profiles.select_related('certificate_profile').all()

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

    def set_allowed_cert_profiles(self, allowed_profile_data: dict[str, str]) -> set[tuple[str, str]]:
        """Sets the certificate profiles allowed in the domain.

        Args:
            allowed_profile_data: Dict where key is allowed certificate profile ID (str) and value is optional alias

        Returns:
            Set of rejected aliases due to duplication in the form of (alias, profile unique name)
        """
        existing_aliases = set()
        rejected_aliases = set()
        with transaction.atomic():
            self.certificate_profiles.all().delete()
            for profile in CertificateProfileModel.objects.all():
                id_str = str(profile.id)
                is_allowed = id_str in allowed_profile_data
                alias_value = allowed_profile_data.get(id_str, '')
                if not is_allowed:
                    continue

                if alias_value:
                    if alias_value in existing_aliases:
                        rejected_aliases.add((alias_value, profile.unique_name))
                        alias_value = ''
                    else:
                        existing_aliases.add(alias_value)

                # Create new relation
                DomainAllowedCertificateProfileModel.objects.create(
                    domain=self,
                    certificate_profile=profile,
                    alias=alias_value
                )

        return rejected_aliases


    def _add_default_profiles(self) -> None:
        """Adds default certificate profiles to the domain as allowed."""
        default_profiles = CertificateProfileModel.objects.filter(is_default=True)
        for profile in default_profiles:
            DomainAllowedCertificateProfileModel.objects.get_or_create(
                domain=self,
                certificate_profile=profile,
            )



class DomainAllowedCertificateProfileModel(models.Model):
    """Model representing allowed certificate profiles for a domain."""

    domain = models.ForeignKey(
        DomainModel,
        on_delete=models.CASCADE,
        related_name='certificate_profiles'
    )
    certificate_profile = models.ForeignKey(
        CertificateProfileModel,
        on_delete=models.CASCADE,
        related_name='domains'
    )
    # Domain-specific alias for the certificate profile name
    alias = models.CharField(max_length=255, default='')

    class Meta(TypedModelMeta):
        """Meta information."""
        constraints: ClassVar = [
            # allow duplicate empty aliases
            models.UniqueConstraint(
                fields=['domain', 'alias'],
                name='unique_domain_alias_when_not_empty',
                condition=~Q(alias=''),
            ),
            models.UniqueConstraint(
                fields=['domain', 'certificate_profile'],
                name='unique_domain_certificate_profile'
            ),
        ]

    def __str__(self) -> str:
        """String representation of the DomainAllowedCertificateProfileModel."""
        name_str = f'{self.domain.unique_name} - {self.certificate_profile.unique_name}'
        if self.alias:
            name_str += f' (alias: {self.alias})'
        return name_str

