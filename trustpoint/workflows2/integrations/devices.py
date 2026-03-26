"""Signal integration that emits Workflow 2 events for device changes."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from django.db.models.signals import post_save, pre_delete, pre_save
from django.dispatch import receiver

from devices.models import DeviceModel
from request.request_context import BaseRequestContext
from request.workflows2_handler import Workflow2Handler
from workflows2.events.request_events import Events

if TYPE_CHECKING:
    from django.db.models.base import ModelBase


@receiver(pre_save, sender=DeviceModel)
def cache_old_domain(
    sender: ModelBase,  # noqa: ARG001
    instance: DeviceModel,
    **_kwargs: Any,
) -> None:
    """Cache the previous domain ID so Workflow 2 can detect domain moves."""
    instance.old_domain_id = DeviceModel.objects.get(pk=instance.pk).domain_id if instance.pk else None  # type: ignore[attr-defined]


@receiver(post_save, sender=DeviceModel)
def on_device_saved(
    sender: type[DeviceModel],  # noqa: ARG001
    instance: DeviceModel,
    created: bool,  # noqa: FBT001
    **_kwargs: Any,
) -> None:
    """Dispatch Workflow 2 runs for supported device lifecycle changes."""
    if created:
        context = BaseRequestContext(
            event=Events.device_created,
            device=instance,
            domain=instance.domain,
            protocol=Events.device_created.protocol,
            operation=Events.device_created.operation,
        )
        Workflow2Handler().handle(context)
        return

    old_domain_id = getattr(instance, 'old_domain_id', None)
    if old_domain_id != instance.domain_id and instance.domain_id is not None:
        context = BaseRequestContext(
            event=Events.device_domain_changed,
            device=instance,
            domain=instance.domain,
            protocol=Events.device_domain_changed.protocol,
            operation=Events.device_domain_changed.operation,
        )
        Workflow2Handler().handle(context)


@receiver(pre_delete, sender=DeviceModel)
def on_device_deleted(
    sender: type[DeviceModel],  # noqa: ARG001
    instance: DeviceModel,
    **_kwargs: Any,
) -> None:
    """Dispatch Workflow 2 runs before a device is deleted."""
    context = BaseRequestContext(
        event=Events.device_deleted,
        device=instance,
        domain=instance.domain,
        protocol=Events.device_deleted.protocol,
        operation=Events.device_deleted.operation,
    )
    Workflow2Handler().handle(context)
