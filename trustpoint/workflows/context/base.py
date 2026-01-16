"""Base types for workflow context catalog strategies.

These strategies build design-time variable catalogs for the UI wizard.
They do not assemble runtime execution context.
"""

from __future__ import annotations

from typing import Any


class ContextStrategy:
    """Base class for context *catalog* strategies.

    These strategies are used ONLY for the UI variable catalog (wizard/help):
    they return groups of variables with dot-paths and sample values.

    They are NOT used to build runtime template context.
    """

    handler: str = ''

    def get_design_time_groups(
        self,
        *,
        protocol: str | None = None,
        operation: str | None = None,
    ) -> list[dict[str, Any]]:
        """Return grouped variable catalog entries for the given instance."""
        raise NotImplementedError
