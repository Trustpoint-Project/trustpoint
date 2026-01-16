"""Registry for context strategies.

Context strategies are registered by handler key (e.g. "certificate_request", "device_action").
They are used to build or enrich the runtime context used by executors and the UI.

Rules:
- Handler keys must be unique.
- Duplicate registration is treated as an error to prevent accidental overrides.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Final

if TYPE_CHECKING:
    from workflows.context.base import ContextStrategy

_REGISTRY: Final[dict[str, type[ContextStrategy]]] = {}


def register(strategy_cls: type[ContextStrategy]) -> type[ContextStrategy]:
    """Class decorator: register a strategy class by its ``handler`` attribute.

    Raises:
        ValueError: if handler is missing/empty or already registered.
    """
    handler = getattr(strategy_cls, 'handler', '') or ''
    handler = str(handler).strip()
    if not handler:
        msg = "Strategy must define a non-empty 'handler' attribute."
        raise ValueError(msg)

    if handler in _REGISTRY and _REGISTRY[handler] is not strategy_cls:
        msg = (
            f"Handler '{handler}' already registered with {_REGISTRY[handler].__name__}; "
            f"cannot override with {strategy_cls.__name__}."
        )
        raise ValueError(
            msg
        )

    _REGISTRY[handler] = strategy_cls
    return strategy_cls


def get_strategy(handler: str) -> ContextStrategy:
    """Return an instantiated strategy for the given handler.

    Raises:
        ValueError: if handler is not registered.
    """
    key = str(handler or '').strip()
    cls = _REGISTRY.get(key)
    if not cls:
        msg = f"No context strategy defined for handler '{key}'. Registered={sorted(_REGISTRY.keys())}"
        raise ValueError(msg)
    return cls()


def try_get_strategy(handler: str) -> ContextStrategy | None:
    """Return strategy instance if registered, else None."""
    key = str(handler or '').strip()
    cls = _REGISTRY.get(key)
    return cls() if cls else None


def all_strategies() -> dict[str, type[ContextStrategy]]:
    """Return a copy of the registry (for introspection/testing)."""
    return dict(_REGISTRY)
