"""Contains logging utilities for the trustpoint project."""
from __future__ import annotations

import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Any


class LoggerMixin:
    """Mixin that adds log features to the subclass."""

    logger: logging.Logger

    @classmethod
    def __init_subclass__(cls, **kwargs: Any) -> None:
        """Adds an appropriate logger to the subclass and makes it available through cls.logger."""
        super().__init_subclass__(**kwargs)

        cls.logger = logging.getLogger('trustpoint').getChild(cls.__module__).getChild(cls.__name__)
