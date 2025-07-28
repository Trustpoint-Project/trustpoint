# workflows/services/trigger_dispatcher.py
from collections.abc import Callable
from typing import Any


class TriggerDispatcher:
    """Central registry for named workflow triggers."""
    _handlers: dict[str, Callable[..., dict[str, Any]]] = {}

    @classmethod
    def register(cls, name: str, handler: Callable[..., dict[str, Any]]) -> None:
        """Register a handler function under this trigger name.

        Handler signature: (**event_kwargs) -> dict(status=..., …)
        """
        cls._handlers[name] = handler

    @classmethod
    def dispatch(cls, name: str, **event: Any) -> dict[str, Any]:
        """Look up the handler for `name` and call it with the event payload.

        Returns the handler’s status dict, or a no_handler error.
        """
        handler = cls._handlers.get(name)
        if not handler:
            return {'status': 'no_handler', 'error': f'No trigger registered for {name!r}'}
        return handler(**event)
