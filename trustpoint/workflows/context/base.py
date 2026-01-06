from __future__ import annotations

from typing import Any


class ContextStrategy:
    """Base class for all context strategies.

    Each strategy produces:
      - variables: descriptors for UI (key → label)
      - values: actual values extracted from the runtime context
    """

    key: str = 'base'
    label: str = 'Base Strategy'

    # UI descriptions of variables provided by this strategy
    variables: dict[str, str] = {}

    def get_variables(self) -> dict[str, str]:
        """Return UI-descriptive metadata."""
        return self.variables

    def get_values(self, ctx: dict[str, Any]) -> dict[str, Any]:
        """Compute runtime values for the strategy-specific variables."""
        raise NotImplementedError
