# workflows2/integrations/devices.py
from __future__ import annotations

from typing import Any

from django.db.models.signals import post_save
from django.dispatch import receiver

from devices.models import DeviceModel
from workflows2.events.triggers import Triggers
from workflows2.services.dispatch import EventSource, WorkflowDispatchService


@receiver(post_save, sender=DeviceModel)
def on_device_created(sender: type[DeviceModel], instance: DeviceModel, created: bool, **_kwargs: Any) -> None:
    if not created:
        return

    event = {
        "device": {
            "id": str(instance.id),
            "common_name": instance.common_name,
            "serial_number": instance.serial_number,
            "domain_id": instance.domain_id,
        }
    }

    source = EventSource(
        trustpoint=True,
        domain_id=instance.domain_id,
        device_id=str(instance.id),
    )

    WorkflowDispatchService().emit_event(
        on=Triggers.DEVICE_CREATED,
        event=event,
        source=source,
        initial_vars={},
    )
