"""Signal integration that emits Workflow 2 events for device changes."""

from __future__ import annotations

from typing import Any

from django.db.models.signals import post_save
from django.dispatch import receiver

from devices.models import DeviceModel
from request.request_context import BaseRequestContext
from request.workflows2_handler import Workflow2Handler
from workflows.events import Events


@receiver(post_save, sender=DeviceModel)
def on_device_created(
    sender: type[DeviceModel],  # noqa: ARG001
    instance: DeviceModel,
    created: bool,  # noqa: FBT001
    **_kwargs: Any,
) -> None:
    """Dispatch Workflow 2 runs for newly created devices."""
    if not created:
        return

    context = BaseRequestContext(
        event=Events.device_created,
        device=instance,
        domain=instance.domain,
        protocol=Events.device_created.protocol,
        operation=Events.device_created.operation,
    )
    Workflow2Handler().handle(context)
