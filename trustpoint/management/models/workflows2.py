"""Workflows2 config Model."""
from __future__ import annotations

from django.db import models
from django.utils.translation import gettext_lazy as _


class WorkflowExecutionConfig(models.Model):
    class Mode(models.TextChoices):
        AUTO = "auto", _("Automatic (use worker if available, else inline)")
        INLINE = "inline", _("Inline (run immediately in web process)")
        QUEUE = "queue", _("Queued (requires worker)")

    # singleton (pk=1)
    mode = models.CharField(max_length=16, choices=Mode.choices, default=Mode.AUTO)

    worker_stale_after_seconds = models.PositiveIntegerField(
        default=30,
        help_text=_("If last worker heartbeat is older than this, treat worker as unavailable.")
    )

    last_updated = models.DateTimeField(auto_now=True)

    def save(self, *args, **kwargs):
        self.pk = 1
        super().save(*args, **kwargs)

    @classmethod
    def load(cls) -> "WorkflowExecutionConfig":
        obj, _ = cls.objects.get_or_create(pk=1)
        return obj
