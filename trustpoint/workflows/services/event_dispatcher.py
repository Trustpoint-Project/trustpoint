"""Dispatch workflow events to registered handlers.

Resolves a trigger (by key or `Trigger` instance) and invokes the handler
registered under the trigger's handler key, returning the handler's result.
"""

from __future__ import annotations

from typing import Any, Protocol, cast

from workflows.triggers import Trigger, Triggers

from .handler_lookup import get_handler_by_key


class Handler(Protocol):
    """Callable handler instance contract."""

    def __call__(self, *, protocol: str, operation: str, **kwargs: Any) -> dict[str, Any]:
        """Callable handler instance contract."""
        ...


class EventDispatcher:
    """Dispatch events for workflow triggers."""

    @classmethod
    def dispatch(cls, trigger: str | Trigger, **kwargs: Any) -> dict[str, Any]:
        """Dispatch a trigger to its registered handler.

        Args:
            trigger: Either a trigger key (``str``) or a `Trigger` instance.
            **kwargs: Extra keyword arguments passed through to the handler.

        Returns:
            A dictionary result returned by the handler. If no trigger or handler
            matches, returns ``{"status": "no_match"}``.
        """
        # Resolve Trigger instance.
        trig: Trigger | None
        if isinstance(trigger, Trigger):
            trig = trigger
        else:
            trig = None
            for t in Triggers.all():
                if t.key == trigger:
                    trig = t
                    break

        if trig is None:
            return {'status': 'no_match'}

        handler_cls = get_handler_by_key(trig.handler)
        if handler_cls is None:
            return {'status': 'no_match'}

        # Create instance and assert it matches our callable protocol.
        handler = cast('Handler', handler_cls())
        return handler(protocol=trig.protocol, operation=trig.operation, **kwargs)
