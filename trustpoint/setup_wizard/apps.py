"""Configuration for the setup wizard app."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from django.apps import AppConfig

if TYPE_CHECKING:
    from typing import Any


class SetupWizardConfig(AppConfig):
    """Configuration for the setup wizard app."""

    default_auto_field = 'django.db.models.BigAutoField'
    name = 'setup_wizard'

    logger: logging.Logger

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """Initializes the configuration for the setup wizard app.

        Args:
            *args: Any positional arguments will be passed to the super constructor.
            **kwargs: Any keyword arguments will be passed to the super constructor.
        """
        self.logger = logging.getLogger('tp').getChild('setup_wizard').getChild(self.__class__.__name__)
        super().__init__(*args, **kwargs)
