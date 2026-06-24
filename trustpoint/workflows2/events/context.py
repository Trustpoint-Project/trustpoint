"""Context variable metadata used by Workflow 2 triggers."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from django.utils.encoding import force_str
from django.utils.functional import Promise

TranslatedText = str | Promise

GROUP_PATH_PARTS = 2


@dataclass(frozen=True)
class ContextVar:
    """One entry in the variable catalog.

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
    type: str = 'any'
    description: TranslatedText = ''
    example: Any = None

    title: TranslatedText = ''
    group: TranslatedText = ''
    help_text: TranslatedText = ''

    @property
    def template(self) -> str:
        """Return the `${...}` template form for this context variable."""
        return '${' + force_str(self.path) + '}'

    @property
    def label(self) -> str:
        """Return the UI label for this context variable."""
        title = force_str(self.title or '').strip()
        if title:
            return title
        path = force_str(self.path or '')
        last = path.split('.')[-1] if path else ''
        return last.replace('_', ' ').strip() or self.path

    @property
    def resolved_group(self) -> str:
        """Return the group name used for picker organization."""
        g = force_str(self.group or '').strip()
        if g:
            return g

        path = force_str(self.path or '')
        parts = [p for p in path.split('.') if p]
        if len(parts) >= GROUP_PATH_PARTS:
            return '.'.join(parts[:GROUP_PATH_PARTS])
        if len(parts) == 1:
            return parts[0]
        return 'other'

    def to_dict(self) -> dict[str, Any]:
        """Serialize the context variable for JSON catalog responses."""
        return {
            'path': force_str(self.path),
            'type': force_str(self.type),
            'description': force_str(self.description or ''),
            'example': self.example,
            'title': self.label,
            'group': self.resolved_group,
            'template': self.template,
            'help_text': force_str(self.help_text or ''),
        }
