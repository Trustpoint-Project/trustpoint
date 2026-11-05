# Copyright (c) 2024 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Create GDS Push configuration and schedule its periodic tasks."""

from typing import Any

from django.db.models.base import ModelBase
from django.db.models.signals import post_save
from django.dispatch import receiver

from devices.models import DeviceModel, OpcUaGdsPushConfig


@receiver(post_save, sender=DeviceModel)
def create_gds_push_config(
    sender: ModelBase,  # noqa: ARG001
    instance: DeviceModel,
    **kwargs: Any,  # noqa: ARG001
) -> None:
    """Give OPC UA GDS Push devices their own configuration."""
    if instance.device_type == DeviceModel.DeviceType.OPC_UA_GDS_PUSH:
        OpcUaGdsPushConfig.objects.get_or_create(device=instance)


@receiver(post_save, sender=OpcUaGdsPushConfig)
def schedule_gds_push_updates(
    sender: ModelBase,  # noqa: ARG001
    instance: OpcUaGdsPushConfig,
    *,
    created: bool,
    update_fields: frozenset[str] | None,
    **kwargs: Any,  # noqa: ARG001
) -> None:
    """Schedule renewals when settings change, retaining device IDs as task arguments."""
    server_fields = {'opc_gds_push_enable_periodic_update', 'opc_gds_push_renewal_interval'}
    domain_fields = {
        'opc_gds_push_enable_domain_credential_renewal',
        'opc_gds_push_domain_credential_renewal_interval',
    }
    if created or update_fields is None:
        return
    if server_fields.intersection(update_fields):
        instance.schedule_next_gds_push_update()
    if domain_fields.intersection(update_fields):
        instance.schedule_next_gds_push_domain_credential_renewal()
