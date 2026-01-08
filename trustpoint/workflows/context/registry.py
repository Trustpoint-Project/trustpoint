from __future__ import annotations

from workflows.context.base import ContextStrategy

_REGISTRY: dict[str, type[ContextStrategy]] = {}


def register(strategy_cls: type[ContextStrategy]) -> type[ContextStrategy]:
    """Class decorator: register a strategy class by its handler attribute."""
    handler = getattr(strategy_cls, 'handler', '') or ''
    if not handler:
        raise ValueError("Strategy must define a non-empty 'handler' attribute.")
    _REGISTRY[handler] = strategy_cls
    return strategy_cls


def get_strategy(handler: str) -> ContextStrategy:
    """Return an instantiated strategy for the given handler."""
    cls = _REGISTRY.get(handler)
    if not cls:
        msg = f"No context strategy defined for handler '{handler}'. Registered={list(_REGISTRY.keys())}"
        raise ValueError(msg)
    return cls()


def all_strategies() -> dict[str, type[ContextStrategy]]:
    """Return a copy of the registry."""
    return dict(_REGISTRY)
