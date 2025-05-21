import logging

from django.apps import AppConfig


class SetupWizardConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'setup_wizard'

    logger: logging.Logger

    def __init__(self, *args, **kwargs):
        self.logger = logging.getLogger('tp').getChild('setup_wizard').getChild(self.__class__.__name__)
        super().__init__(*args, **kwargs)
