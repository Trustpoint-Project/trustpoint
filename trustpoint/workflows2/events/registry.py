# workflows2/events/registry.py
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from workflows2.events.context import ContextVar


@dataclass(frozen=True)
class EventSpec:
    """
    A trigger key (trigger.on) that is allowed in workflows.

    allowed_step_types:
      - None => allow all step types (compiler built-ins still apply)
      - set(...) => only these step types may appear in workflow.steps for this trigger
    """
    key: str
    title: str = ""
    description: str = ""
    allowed_step_types: set[str] | None = None
    context_vars: tuple[ContextVar, ...] = ()


class EventRegistry:
    def __init__(self, specs: Iterable[EventSpec] | None = None) -> None:
        self._specs: dict[str, EventSpec] = {}
        if specs:
            self.register_many(specs)

    def register(self, spec: EventSpec) -> None:
        key = (spec.key or "").strip()
        if not key:
            raise ValueError("EventSpec.key must be non-empty")

        allowed = spec.allowed_step_types
        if allowed is not None:
            allowed = {str(x).strip() for x in allowed if str(x).strip()}
            allowed = allowed or set()

        ctx_vars: list[ContextVar] = []
        for v in (spec.context_vars or ()):
            p = (v.path or "").strip()
            if not p:
                continue

            ctx_vars.append(
                ContextVar(
                    path=p,
                    type=str(v.type or "any"),
                    description=str(v.description or ""),
                    example=v.example,
                    title=str(v.title or ""),
                    group=str(v.group or ""),
                    help_text=str(v.help_text or ""),
                )
            )

        self._specs[key] = EventSpec(
            key=key,
            title=str(spec.title or "").strip(),
            description=str(spec.description or ""),
            allowed_step_types=allowed,
            context_vars=tuple(ctx_vars),
        )

    def register_many(self, specs: Iterable[EventSpec]) -> None:
        for s in specs:
            self.register(s)

    def is_known(self, key: str) -> bool:
        return (key or "").strip() in self._specs

    def get(self, key: str) -> EventSpec | None:
        return self._specs.get((key or "").strip())

    def all_keys(self) -> list[str]:
        return sorted(self._specs.keys())

    def all_specs(self) -> list[EventSpec]:
        return [self._specs[k] for k in self.all_keys()]

    def describe(self, key: str) -> str | None:
        spec = self.get(key)
        return spec.description if spec else None

    def context_for(self, key: str) -> tuple[ContextVar, ...]:
        spec = self.get(key)
        return spec.context_vars if spec else ()


_REGISTRY = EventRegistry()


def get_event_registry() -> EventRegistry:
    return _REGISTRY
