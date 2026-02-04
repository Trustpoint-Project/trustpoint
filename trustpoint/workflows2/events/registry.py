from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable


@dataclass(frozen=True)
class EventSpec:
    key: str
    description: str


class EventRegistry:
    """
    Central allowlist of valid trigger.on values.
    Keeps compiler strict and runtime predictable.
    """

    def __init__(self, specs: Iterable[EventSpec]) -> None:
        self._specs = {s.key: s for s in specs}

    def is_known(self, key: str) -> bool:
        return key in self._specs

    def all_keys(self) -> list[str]:
        return sorted(self._specs.keys())

    def describe(self, key: str) -> str | None:
        spec = self._specs.get(key)
        return spec.description if spec else None


_DEFAULT = EventRegistry(
    specs=[
        EventSpec("device.created", "A device object was created."),
        # Add more as you implement them:
        # EventSpec("device.updated", "A device object was updated."),
        # EventSpec("enrollment.created", "An enrollment request was created."),
    ]
)


def get_event_registry() -> EventRegistry:
    return _DEFAULT
