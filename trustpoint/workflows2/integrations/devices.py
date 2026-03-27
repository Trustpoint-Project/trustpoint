"""Signal integration that emits Workflow 2 events for device changes."""

from __future__ import annotations

from contextlib import suppress
from typing import TYPE_CHECKING, Any

from django.db.models.signals import post_save, pre_delete, pre_save
from django.dispatch import receiver

from devices.models import DeviceModel
from request.request_context import BaseRequestContext
from request.workflows2_handler import Workflow2Handler
from workflows2.events.payloads import build_device_changes, build_device_snapshot
from workflows2.events.request_events import Events

if TYPE_CHECKING:
    from django.db.models.base import ModelBase


@receiver(pre_save, sender=DeviceModel)
def cache_previous_device_snapshot(
    sender: ModelBase,  # noqa: ARG001
    instance: DeviceModel,
    **_kwargs: Any,
) -> None:
    """Cache the previous device state so Workflow 2 can emit update diffs."""
    if not instance.pk:
        instance.workflow2_before_snapshot = None  # type: ignore[attr-defined]
        return

    with suppress(DeviceModel.DoesNotExist):
        previous = DeviceModel.objects.get(pk=instance.pk)
        instance.workflow2_before_snapshot = build_device_snapshot(previous)  # type: ignore[attr-defined]


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

    before = getattr(instance, 'workflow2_before_snapshot', None)
    after = build_device_snapshot(instance)
    changes = build_device_changes(before, after)
    if not changes:
        return

    context = BaseRequestContext(
        event=Events.device_updated,
        event_payload={
            'device': {
                **after,
                'before': before or {},
                'after': after,
                'changes': changes,
            },
        },
        device=instance,
        domain=instance.domain,
        protocol=Events.device_updated.protocol,
        operation=Events.device_updated.operation,
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
