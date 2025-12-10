from typing import Any

from django.db.models.signals import post_save, pre_save
from django.db.models.base import ModelBase
from django.dispatch import receiver
from request.request_context import RequestContext
from request.workflow_handler import WorkflowHandler
from workflows.events import Events

from devices.models import DeviceModel


@receiver(pre_save, sender=DeviceModel)
def _cache_old_domain(sender: ModelBase, instance: DeviceModel, **_: Any) -> None:
    instance._old_domain_id = DeviceModel.objects.get(pk=instance.pk).domain_id if instance.pk else None


@receiver(post_save, sender=DeviceModel)
def _trigger_device_events(sender: ModelBase, instance: DeviceModel, created: bool, **_: Any) -> None:
    handler = WorkflowHandler()

    # 1) Device created
    if created:
        ctx = RequestContext(
            event=Events.device_created,
            device=instance,
            domain=instance.domain,
            protocol='device',
            operation='created',
        )
        handler.handle(ctx)
        return

    # 2) Device onboarded
    old = getattr(instance, '_old_domain_id', None)
    new = instance.domain_id

    if old != new and new is not None:
        ctx = RequestContext(
            event=Events.device_onboarded,
            device=instance,
            domain=instance.domain,
            protocol='device',
            operation='onboarded',
        )
        handler.handle(ctx)
