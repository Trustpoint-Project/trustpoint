# workflows2/integrations/devices.py
from __future__ import annotations

from typing import Any

from django.db.models.signals import post_save
from django.dispatch import receiver

from devices.models import DeviceModel
from request.request_context import BaseRequestContext
from request.workflows2_handler import Workflow2Handler
from workflows.events import Events


@receiver(post_save, sender=DeviceModel)
def on_device_created(sender: type[DeviceModel], instance: DeviceModel, created: bool, **_kwargs: Any) -> None:
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
