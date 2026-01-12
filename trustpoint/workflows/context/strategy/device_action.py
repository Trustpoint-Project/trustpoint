"""Context catalog strategy for device lifecycle actions.

This module provides the wizard variable catalog for the `device_action` handler.
"""

from __future__ import annotations

from typing import Any

from workflows.context.base import ContextStrategy
from workflows.context.registry import register

from .common import common_instance_group, common_workflow_group


@register
class DeviceActionContextStrategy(ContextStrategy):
    """Context catalog strategy for the `device_action` handler."""
    handler = 'device_action'

    def get_design_time_groups(
        self,
        *,
        protocol: str | None = None,
        operation: str | None = None,
    ) -> list[dict[str, Any]]:
        """Return design-time variable groups for the wizard."""
        return [
            common_workflow_group(),
            common_instance_group(),
            {
                'name': 'Device',
                'vars': [
                    {'path': 'ctx.device.common_name', 'label': 'Device common name', 'sample': None},
                    {'path': 'ctx.device.serial_number', 'label': 'Device serial number', 'sample': None},
                    {'path': 'ctx.device.domain', 'label': 'Device domain', 'sample': None},
                    {'path': 'ctx.device.device_type', 'label': 'Device type', 'sample': None},
                    {'path': 'ctx.device.created_at', 'label': 'Device created at', 'sample': None},
                ],
            },
            {
                'name': 'Request',
                'vars': [
                    {'path': 'ctx.request.protocol', 'label': 'Protocol', 'sample': protocol or 'device'},
                    {'path': 'ctx.request.operation', 'label': 'Operation', 'sample': operation},
                    {'path': 'ctx.request.device_request_id', 'label': 'Device request ID', 'sample': None},
                ],
            },
            {
                'name': 'Saved Vars',
                'vars': [
                    {'path': 'ctx.vars.*', 'label': 'Saved Vars', 'sample': None},
                ],
            },
        ]
