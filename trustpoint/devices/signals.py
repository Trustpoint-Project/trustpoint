"""Signals for device model events."""

from typing import Any

from django.db.models.base import ModelBase
from django.db.models.signals import post_save, pre_save
from django.dispatch import receiver

from devices.models import DeviceModel
from request.request_context import BaseRequestContext
from request.workflow_handler import WorkflowHandler
from workflows.events import Events


@receiver(pre_save, sender=DeviceModel)
def _cache_old_domain(sender: ModelBase, instance: DeviceModel, **_: Any) -> None:  # noqa: ARG001
    """Cache the old domain_id before saving to detect domain changes."""
    instance.old_domain_id = DeviceModel.objects.get(pk=instance.pk).domain_id if instance.pk else None  # type: ignore[attr-defined]


@receiver(post_save, sender=DeviceModel)
def _trigger_device_events(sender: ModelBase, instance: DeviceModel, *, created: bool, **_: Any) -> None:  # noqa: ARG001
    handler = WorkflowHandler()

    # 1) Device created
    if created:
        ctx = BaseRequestContext(  # Prob. better not to use Workflow Pipeline here (or add DeviceEventRequestContext)
            event=Events.device_created,
            device=instance,
            domain=instance.domain,
            protocol='device',
            operation='created',
        )
        handler.handle(ctx)
        return

    # 2) Device onboarded
    old = getattr(instance, 'old_domain_id', None)
    new = instance.domain_id

    if old != new and new is not None:
        ctx = BaseRequestContext(
            event=Events.device_onboarded,
            device=instance,
            domain=instance.domain,
            protocol='device',
            operation='onboarded',
        )
        handler.handle(ctx)
