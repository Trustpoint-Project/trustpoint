# workflows2/events/context.py
from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class ContextVar:
    """
    One entry in the variable catalog.

    path:
      Exact path users type in templates.
      Example: "event.device.serial_number"

    type:
      Lightweight value type hint for editor help and validation UI.
      Example: "string", "int", "bool", "uuid", "object", "array"

    title:
      Human-friendly label for the UI. Optional.
      If blank, frontend may derive one from the path.

    group:
      Optional picker group. Example: "event.device", "event.est".
      If blank, frontend/backend may derive a fallback from the path.

    help_text:
      Optional extra explanation for the editor UI.
    """
    path: str
    type: str = "any"
    description: str = ""
    example: Any = None

    title: str = ""
    group: str = ""
    help_text: str = ""

    @property
    def template(self) -> str:
        return "${" + self.path + "}"

    @property
    def label(self) -> str:
        if self.title.strip():
            return self.title.strip()
        last = self.path.split(".")[-1] if self.path else ""
        return last.replace("_", " ").strip() or self.path

    @property
    def resolved_group(self) -> str:
        g = self.group.strip()
        if g:
            return g

        parts = [p for p in self.path.split(".") if p]
        if len(parts) >= 2:
            return ".".join(parts[:2])
        if len(parts) == 1:
            return parts[0]
        return "other"

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "type": self.type,
            "description": self.description,
            "example": self.example,
            "title": self.label,
            "group": self.resolved_group,
            "template": self.template,
            "help_text": self.help_text,
        }
