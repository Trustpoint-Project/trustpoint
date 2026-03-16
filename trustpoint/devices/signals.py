"""Signals for device model events."""
from typing import Any

from django.db.models.base import ModelBase
from django.db.models.signals import post_save, pre_delete, pre_save
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
            protocol=Events.device_created.protocol,
            operation=Events.device_created.operation,
        )
        handler.handle(ctx)
        return

    # 2) Device onboarded (domain changed from old→new)
    old = getattr(instance, 'old_domain_id', None)
    new = instance.domain_id

    if old != new and new is not None:
        ctx = BaseRequestContext(
            event=Events.device_domain_changed,
            device=instance,
            domain=instance.domain,
            protocol=Events.device_domain_changed.protocol,
            operation=Events.device_domain_changed.operation,
        )
        handler.handle(ctx)


@receiver(pre_delete, sender=DeviceModel)
def _trigger_device_deleted(sender: ModelBase, instance: DeviceModel, **_: Any) -> None:
    """Trigger the device_deleted workflow event when a device is removed."""
    ctx = BaseRequestContext(
        event=Events.device_deleted,
        device=instance,
        domain=instance.domain,
        protocol=Events.device_deleted.protocol,
        operation=Events.device_deleted.operation,
    )
    WorkflowHandler().handle(ctx)


@receiver(post_save, sender=DeviceModel)
def schedule_gds_push_update_on_enable(
    sender: ModelBase,  # noqa: ARG001
    instance: DeviceModel,
    *,
    created: bool,
    update_fields: frozenset[str] | None,
    **kwargs: Any,  # noqa: ARG001
) -> None:
    """Schedule a GDS Push periodic update when the feature is toggled on for a device.

    Mirrors the CRL cycle scheduling pattern: whenever ``opc_gds_push_enable_periodic_update``
    is flipped to ``True`` via a save with explicit ``update_fields``, the first update is
    immediately scheduled via Django-Q2.

    Args:
        sender: The model class.
        instance: The DeviceModel instance that was saved.
        created: Whether the instance was just created.
        update_fields: The fields that were updated, or None if not specified.
        **kwargs: Additional keyword arguments.
    """
    if created:
        return

    if (
        update_fields
        and 'opc_gds_push_enable_periodic_update' in update_fields
        and instance.opc_gds_push_enable_periodic_update
    ):
        instance.schedule_next_gds_push_update()
