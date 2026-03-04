# workflows2/events/context.py
from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class ContextVar:
    """
    One entry in the variable catalog.

    path:
      Use the exact string users type in templates.
      Example: "event.device.serial_number"
    """
    path: str
    type: str = "any"  # "string", "int", "bool", "object", "array", "uuid", ...
    description: str = ""
    example: Any = None
