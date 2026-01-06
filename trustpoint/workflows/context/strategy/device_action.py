# workflows/context/strategy/device_action.py

from typing import Any

from workflows.context.base import BaseContextStrategy
from workflows.context.registry import register

from .common import common_instance_group, common_workflow_group


@register
class DeviceActionContextStrategy(BaseContextStrategy):
    handler = 'device_action'

    def get_groups(self, instance: dict[str, Any]) -> list[dict[str, Any]]:
        device = getattr(instance, 'device_request', None).device

        return [
            common_workflow_group(instance),
            common_instance_group(instance),

            {
                'name': 'Device',
                'vars': [
                    {'path': 'ctx.device.common_name', 'label': 'Device common name', 'sample': device.common_name},
                    {'path': 'ctx.device.serial_number', 'label': 'Device serial number', 'sample': device.serial_number},
                    {'path': 'ctx.device.domain', 'label': 'Device domain', 'sample': device.domain.unique_name if device.domain else None},
                    {'path': 'ctx.device.device_type', 'label': 'Device type', 'sample': device.device_type},
                ],
            },

            {
                'name': 'Saved Vars',
                'vars': [
                    {'path': 'ctx.vars.*', 'label': 'Saved Vars', 'sample': None},
                ],
            },
        ]
