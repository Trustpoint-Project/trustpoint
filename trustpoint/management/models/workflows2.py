"""Workflows2 config Model."""
from __future__ import annotations

from typing import Any

from django.db import models
from django.utils.translation import gettext_lazy as _


class WorkflowExecutionConfig(models.Model):
    """Persist the global Workflow 2 execution mode and worker liveness settings."""

    class Mode(models.TextChoices):
        """Supported execution strategies for Workflow 2 dispatch."""

        AUTO = 'auto', _('Automatic (use worker if available, else inline)')
        INLINE = 'inline', _('Inline (run immediately in web process)')
        WORKER = 'worker', _('Worker (requires dedicated worker process)')

    mode = models.CharField(max_length=16, choices=Mode.choices, default=Mode.AUTO)

    worker_stale_after_seconds = models.PositiveIntegerField(
        default=30,
        help_text=_('If last worker heartbeat is older than this, treat worker as unavailable.')
    )

    last_updated = models.DateTimeField(auto_now=True)

    def __str__(self) -> str:
        """Return a concise human-readable representation of the singleton config."""
        return f'Workflow 2 execution config ({self.mode})'

    def save(self, *args: Any, **kwargs: Any) -> None:
        """Persist the singleton config row under the fixed primary key ``1``."""
        self.pk = 1
        super().save(*args, **kwargs)

    @classmethod
    def load(cls) -> WorkflowExecutionConfig:
        """Load the singleton config row, creating it on first access."""
        obj, _ = cls.objects.get_or_create(pk=1)
        return obj
