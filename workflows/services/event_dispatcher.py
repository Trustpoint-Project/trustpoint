# workflows/services/event_dispatcher.py

from typing import Any

from workflows.triggers import Trigger, Triggers

from .handler_lookup import get_handler_by_key


class EventDispatcher:
    @classmethod
    def dispatch(cls, trigger: str | Trigger, **kwargs: Any) -> dict[str, Any]:
        # If they passed in a Trigger instance, use it directly; otherwise look up by key.
        trig = trigger if isinstance(trigger, Trigger) else next((t for t in Triggers.all() if t.key == trigger), None)

        if not trig:
            return {'status': 'no_match'}

        handler_cls = get_handler_by_key(trig.handler)
        if not handler_cls:
            return {'status': 'no_match'}

        handler = handler_cls()
        return handler(protocol=trig.protocol, operation=trig.operation, **kwargs)
