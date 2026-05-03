"""Registry for trigger metadata known to Workflow 2."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from django.utils.encoding import force_str
from django.utils.functional import Promise

from workflows2.events.context import ContextVar

if TYPE_CHECKING:
    from collections.abc import Iterable


TranslatedText = str | Promise


@dataclass(frozen=True)
class EventSpec:
    """A trigger key (trigger.on) that is allowed in workflows.

    allowed_step_types:
      - None => allow all step types (compiler built-ins still apply)
      - set(...) => only these step types may appear in workflow.steps for this trigger
    """
    key: str
    title: TranslatedText = ''
    description: TranslatedText = ''
    group: str = ''
    group_title: TranslatedText = ''
    keywords: tuple[str, ...] = ()
    allowed_step_types: set[str] | None = None
    context_vars: tuple[ContextVar, ...] = ()


class EventRegistry:
    """Store and normalize known event specifications."""

    def __init__(self, specs: Iterable[EventSpec] | None = None) -> None:
        """Initialize the registry with optional initial specs."""
        self._specs: dict[str, EventSpec] = {}
        if specs:
            self.register_many(specs)

    def register(self, spec: EventSpec) -> None:
        """Register or replace one event specification."""
        key = force_str(spec.key or '').strip()
        if not key:
            msg = 'EventSpec.key must be non-empty'
            raise ValueError(msg)

        allowed = spec.allowed_step_types
        if allowed is not None:
            allowed = {str(x).strip() for x in allowed if str(x).strip()}
            allowed = allowed or set()

        ctx_vars: list[ContextVar] = []
        for v in (spec.context_vars or ()):
            p = force_str(v.path or '').strip()
            if not p:
                continue

            ctx_vars.append(
                ContextVar(
                    path=p,
                    type=force_str(v.type or 'any'),
                    description=v.description or '',
                    example=v.example,
                    title=v.title or '',
                    group=v.group or '',
                    help_text=v.help_text or '',
                )
            )

        keywords: list[str] = []
        for raw_keyword in spec.keywords or ():
            keyword = force_str(raw_keyword or '').strip()
            if keyword:
                keywords.append(keyword)

        self._specs[key] = EventSpec(
            key=key,
            title=spec.title or '',
            description=spec.description or '',
            group=force_str(spec.group or '').strip(),
            group_title=spec.group_title or '',
            keywords=tuple(keywords),
            allowed_step_types=allowed,
            context_vars=tuple(ctx_vars),
        )

    def register_many(self, specs: Iterable[EventSpec]) -> None:
        """Register multiple event specifications."""
        for s in specs:
            self.register(s)

    def is_known(self, key: str) -> bool:
        """Return whether the given trigger key is registered."""
        return (key or '').strip() in self._specs

    def get(self, key: str) -> EventSpec | None:
        """Return the registered specification for a trigger key."""
        return self._specs.get((key or '').strip())

    def all_keys(self) -> list[str]:
        """Return all registered trigger keys in sorted order."""
        return sorted(self._specs.keys())

    def all_specs(self) -> list[EventSpec]:
        """Return all registered event specifications in sorted-key order."""
        return [self._specs[k] for k in self.all_keys()]

    def describe(self, key: str) -> str | None:
        """Return the description for a trigger key, if known."""
        spec = self.get(key)
        return force_str(spec.description) if spec else None

    def context_for(self, key: str) -> tuple[ContextVar, ...]:
        """Return the context variables for a trigger key, if known."""
        spec = self.get(key)
        return spec.context_vars if spec else ()


_REGISTRY = EventRegistry()


def get_event_registry() -> EventRegistry:
    """Return the process-wide Workflow 2 event registry."""
    return _REGISTRY
