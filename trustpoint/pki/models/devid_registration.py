"""Model for the DevID Registration."""

from __future__ import annotations

from typing import Any

from django.db import models
from django.utils.translation import gettext_lazy as _
from util.field import UniqueNameValidator

from .domain import DomainModel
from .truststore import TruststoreModel

__all__ = ['DevIdRegistration']


class DevIdRegistration(models.Model):
    """Represents a DevID Registration, linking a Truststore, Domain, unique name, and a serial number regex pattern."""

    objects: models.Manager[DevIdRegistration]

    unique_name = models.CharField(
        verbose_name=_('Unique Name'), max_length=100, unique=True, validators=[UniqueNameValidator()]
    )

    truststore = models.ForeignKey(
        TruststoreModel,
        on_delete=models.CASCADE,
        verbose_name=_('Associated Truststore'),
        related_name='devid_registrations',
    )

    domain = models.ForeignKey(
        DomainModel, on_delete=models.CASCADE, verbose_name=_('Associated Domain'), related_name='devid_registrations'
    )

    serial_number_pattern = models.CharField(
        verbose_name=_('Serial Number Pattern'),
        max_length=255,
        help_text=_('A regex pattern to match valid serial numbers for this registration.'),
    )

    def __str__(self) -> str:
        """Returns a human-readable string representation of the DevIdRegistration instance."""
        return f'DevIdRegistration: {self.unique_name}'

    def save(self, **kwargs: Any) -> None:
        """Ensures the model is valid and enforces validations before saving."""
        self.full_clean()
        super().save(**kwargs)
