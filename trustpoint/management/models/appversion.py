"""App Version Model."""
from __future__ import annotations

from django.db import models
from django.utils.translation import gettext_lazy as _


class AppVersion(models.Model):
    """Model representing the application version and its last update timestamp."""
    objects: models.Manager[AppVersion]

    version = models.CharField(max_length=17)
    container_id = models.CharField(
        max_length=64,
        blank=True,
        default='',
        help_text=_('Container build ID or hash')
    )
    last_updated = models.DateTimeField(auto_now=True)

    class Meta:
        """Meta options for the AppVersion model."""
        verbose_name = 'App Version'

    def __str__(self) -> str:
        """Return a string representation for the AppVersion."""
        build_info = f' (Build: {self.container_id})' if self.container_id else ''
        return f'{self.version}{build_info} @ {self.last_updated.isoformat()}'
