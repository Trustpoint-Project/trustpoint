"""Handler registry for workflow services.

This module provides a decorator to register handler classes under a string key
and a lookup function to retrieve them.
"""

from collections.abc import Callable
from typing import TypeVar, cast

T = TypeVar('T')

# Store concrete classes under a generic-agnostic base to avoid unbound TypeVar at module scope.
_handler_registry: dict[str, type[object]] = {}


def register_handler(key: str) -> Callable[[type[T]], type[T]]:
    """Register an event handler under a given key.

    Intended for use as a class decorator.

    Example:
        >>> @register_handler('certificate_request')
        ... class CertificateRequestHandler:
        ...     pass

    Args:
        key: The unique key under which the handler should be registered.

    Returns:
        A decorator that registers the class and returns it unchanged.
    """

    def decorator(cls: type[T]) -> type[T]:
        _handler_registry[key] = cast('type[object]', cls)
        return cls

    return decorator


def get_handler_by_key(key: str) -> type[object] | None:
    """Look up a handler class by its registry key.

    Args:
        key: The registry key.

    Returns:
        The handler class if found, else None.
    """
    return _handler_registry.get(key)
