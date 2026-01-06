from __future__ import annotations

from workflows.context.base import ContextStrategy
from workflows.context.strategy.registry import StrategyRegistry


class DeviceRequestContextStrategy(ContextStrategy):
    key = 'device_request'
    label = 'Device Request Strategy'

    variables = {
        'action': 'Device action',
        'old_domain': 'Old domain',
        'new_domain': 'New domain',
    }

    def get_values(self, ctx: dict) -> dict:
        req = ctx.get('request') or {}
        return {
            'action': req.get('operation'),
            'old_domain': req.get('old_domain'),
            'new_domain': req.get('new_domain'),
        }


StrategyRegistry.register(DeviceRequestContextStrategy)
