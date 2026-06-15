"""Prometheus Configuration Model."""

from __future__ import annotations

from django.db import models
from django.utils.translation import gettext_lazy as _
from django_stubs_ext.db.models import TypedModelMeta


class PrometheusConfig(models.Model):
    """Stores global configuration for the Prometheus metrics endpoint."""

    objects: models.Manager[PrometheusConfig]

    enabled = models.BooleanField(
        default=False,
        verbose_name=_('Enable Prometheus metrics endpoint'),
        help_text=_('When enabled, the /prometheus/metrics endpoint is available for scraping.'),
    )

    class Meta(TypedModelMeta):
        """Meta class configuration."""

        verbose_name = _('Prometheus Configuration')

    def __str__(self) -> str:
        """Return a human-readable name for the Prometheus configuration."""
        return 'Prometheus Settings'

    @classmethod
    def get(cls) -> PrometheusConfig:
        """Return the singleton Prometheus configuration, creating it if necessary."""
        return cls.objects.first() or cls.objects.create()
