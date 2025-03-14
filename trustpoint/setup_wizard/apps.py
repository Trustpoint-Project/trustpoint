"""App configuration for the TrustPoint setup wizard."""

import logging
from typing import Any

from django.apps import AppConfig


class SetupWizardConfig(AppConfig):
    """Configuration class for the Setup Wizard application."""

    default_auto_field = 'django.db.models.BigAutoField'
    name = 'setup_wizard'

    logger: logging.Logger

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """Initialize the SetupWizardConfig class with logging setup."""
        self.logger = logging.getLogger('tp').getChild('setup_wizard').getChild(self.__class__.__name__)
        super().__init__(*args, **kwargs)
