# workflows/context/registry.py

from workflows.context.base import ContextStrategy

_REGISTRY: dict[str, type[ContextStrategy]] = {}


def register(strategy_cls: type[ContextStrategy]) -> None:
    """Register a strategy class by its handler attribute."""
    if not strategy_cls.handler:
        raise ValueError('Strategy must define a handler attribute.')
    _REGISTRY[strategy_cls.handler] = strategy_cls


def get_strategy(handler: str) -> ContextStrategy:
    """Return an instantiated strategy for the given handler."""
    cls = _REGISTRY.get(handler)
    if not cls:
        msg = f"No context strategy defined for handler '{handler}'"
        raise ValueError(msg)
    return cls()
