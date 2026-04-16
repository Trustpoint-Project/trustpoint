"""Signals for the devices app."""
from typing import Any

from django.db.models.base import ModelBase
from django.db.models.signals import post_save
from django.dispatch import receiver

from devices.models import DeviceModel


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
