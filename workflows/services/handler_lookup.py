# workflows/services/handler_lookup.py

from __future__ import annotations

from collections.abc import Callable
from typing import Any

Handler = Callable[..., dict[str, Any]]  # simplified alias; handlers return dict status

_registry: dict[str, Handler] = {}


def register_handler(name: str, handler: Handler) -> None:
    """Register a handler under a common event name."""
    _registry[name] = handler


def get_handler(name: str) -> Handler:
    """Retrieve a previously registered handler; KeyError if missing."""
    try:
        return _registry[name]
    except KeyError as exc:
        raise KeyError(f'Handler for {name!r} not registered') from exc
