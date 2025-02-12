"""Module that contains the DomainModel."""
from __future__ import annotations

from typing import TYPE_CHECKING

from core.validator.field import UniqueNameValidator
from django.core.exceptions import ValidationError
from django.db import models
from django.utils.translation import gettext_lazy as _

from . import IssuingCaModel

if TYPE_CHECKING:
    from typing import ClassVar

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

    def __str__(self) -> str:
        """Human-readable representation of the Domain model instance.

        Returns:
            str:
                Human-readable representation of the EndpointProfile model instance.
        """
        return self.unique_name

    def save(self, *args: tuple, **kwargs: dict) -> None:
        """Save the Domain model instance."""
        self.clean()  # Ensure validation before saving
        super().save(*args, **kwargs)

    def __repr__(self) -> str:
        """Returns a string representation of the DomainModel instance"""
        return f'DomainModel(unique_name={self.unique_name})'

    def clean(self) -> None:
        """Validate that the issuing CA is not an auto-generated root CA."""
        if self.issuing_ca and self.issuing_ca.issuing_ca_type == IssuingCaModel.IssuingCaTypeChoice.AUTOGEN_ROOT:
            exc_msg = 'The issuing CA associated with the domain cannot be an auto-generated root CA.'
            raise ValidationError(exc_msg)
