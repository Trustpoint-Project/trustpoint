"""Strategy registry for CA rollover strategies."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pki.models.ca_rollover import CaRolloverStrategyType
    from pki.rollover.base import RolloverStrategy

logger = logging.getLogger(__name__)


class RolloverStrategyRegistry:
    """Registry mapping strategy type identifiers to strategy instances.

    Strategies register themselves at module load time. The service and views
    resolve the appropriate strategy from this registry by type identifier.
    """

    def __init__(self) -> None:
        """Initialize an empty registry."""
        self._strategies: dict[CaRolloverStrategyType, RolloverStrategy] = {}

    def register(self, strategy: RolloverStrategy) -> None:
        """Register a rollover strategy."""
        self._strategies[strategy.strategy_type] = strategy
        logger.debug('Registered rollover strategy: %s', strategy.strategy_type)

    def get(self, strategy_type: CaRolloverStrategyType) -> RolloverStrategy:
        """Retrieve a strategy by its type identifier."""
        if strategy_type not in self._strategies:
            msg = f'No rollover strategy registered for type: {strategy_type}'
            raise KeyError(msg)
        return self._strategies[strategy_type]

    def get_available(self) -> list[tuple[str, str]]:
        """Return a list of (type_value, display_name) tuples for available strategies."""
        return [
            (str(s.strategy_type), s.display_name)
            for s in self._strategies.values()
        ]

    def is_registered(self, strategy_type: CaRolloverStrategyType) -> bool:
        """Check whether a strategy type is registered."""
        return strategy_type in self._strategies


rollover_registry = RolloverStrategyRegistry()
