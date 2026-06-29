"""UI configuration model."""

from __future__ import annotations

from django.db import models
from django.utils.translation import gettext_lazy as _


class UIConfig(models.Model):
    """UI configuration model for interface preferences."""

    class ViewModeChoices(models.TextChoices):
        """View mode options."""

        STANDARD = 'standard', _('Standard View')
        SIMPLIFIED = 'simplified', _('Simplified View')

    view_mode = models.CharField(
        max_length=10,
        choices=ViewModeChoices,
        default=ViewModeChoices.STANDARD,
        verbose_name=_('View Mode'),
        help_text=_('Choose between standard sidebar navigation or simplified domain-centric view'),
    )

    last_updated = models.DateTimeField(auto_now=True)

    def __str__(self) -> str:
        """Return a readable string representation of the configuration."""
        return f'UI Config: {self.get_view_mode_display()}'

    @classmethod
    def get_current(cls) -> UIConfig:
        """Return the current UI configuration."""
        config, _ = cls.objects.get_or_create(
            id=1,
            defaults={
                'view_mode': cls.ViewModeChoices.STANDARD,
            },
        )
        return config

    @property
    def is_simplified_mode(self) -> bool:
        """Check if simplified view mode is enabled."""
        return self.view_mode == self.ViewModeChoices.SIMPLIFIED
