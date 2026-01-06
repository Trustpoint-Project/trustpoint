from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from workflows.context.base import ContextStrategy


class StrategyRegistry:
    _registry: dict[str, type[ContextStrategy]] = {}

    @classmethod
    def register(cls, strategy_cls: type[ContextStrategy]) -> None:
        cls._registry[strategy_cls.key] = strategy_cls

    @classmethod
    def get(cls, key: str) -> ContextStrategy:
        if key not in cls._registry:
            msg = f'No context strategy registered for handler: {key}'
            raise KeyError(msg)
        return cls._registry[key]()

    @classmethod
    def all(cls) -> dict[str, type[ContextStrategy]]:
        return dict(cls._registry)
