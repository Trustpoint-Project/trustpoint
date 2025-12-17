"""This Package contains the setup wizard django application."""

from __future__ import annotations

import enum
from pathlib import Path

WIZARD_STATE_PATH = Path('/etc/trustpoint/wizard/state')


class SetupWizardState(enum.Enum):
    """This enum represents the current setup wizard state of the trustpoint."""

    WIZARD_SETUP_CRYPTO_STORAGE = WIZARD_STATE_PATH / Path('WIZARD_SETUP_CRYPTO_STORAGE')
    WIZARD_SETUP_HSM = WIZARD_STATE_PATH / Path('WIZARD_SETUP_HSM')
    WIZARD_SETUP_HSM_AUTORESTORE = WIZARD_STATE_PATH / Path('WIZARD_SETUP_HSM_AUTORESTORE')
    WIZARD_SETUP_MODE = WIZARD_STATE_PATH / Path('WIZARD_SETUP_MODE')
    WIZARD_SELECT_TLS_SERVER_CREDENTIAL = WIZARD_STATE_PATH / Path('WIZARD_SELECT_TLS_SERVER_CREDENTIAL')
    WIZARD_RESTORE = WIZARD_STATE_PATH / Path('WIZARD_RESTORE')
    WIZARD_TLS_SERVER_CREDENTIAL_APPLY = WIZARD_STATE_PATH / Path('WIZARD_TLS_SERVER_CREDENTIAL_APPLY')
    WIZARD_BACKUP_PASSWORD = WIZARD_STATE_PATH / Path('WIZARD_BACKUP_PASSWORD')
    WIZARD_DEMO_DATA = WIZARD_STATE_PATH / Path('WIZARD_DEMO_DATA')
    WIZARD_CREATE_SUPER_USER = WIZARD_STATE_PATH / Path('WIZARD_CREATE_SUPER_USER')
    WIZARD_COMPLETED = WIZARD_STATE_PATH / Path('WIZARD_COMPLETED')
    WIZARD_AUTO_RESTORE_HSM = WIZARD_STATE_PATH / Path('WIZARD_AUTO_RESTORE_HSM')
    WIZARD_AUTO_RESTORE_PASSWORD = WIZARD_STATE_PATH / Path('WIZARD_AUTO_RESTORE_PASSWORD')


    @classmethod
    def get_current_state(cls) -> SetupWizardState:
        """Gets the current setup wizard state of the trustpoint.

        Returns:
            The current setup wizard state.

        Raises:
            RuntimeError: If the current setup wizard state cannot be determined.
        """
        for member in cls:
            if member.value.is_file():
                return member
        err_msg = 'Failed to determine wizard state.'
        raise RuntimeError(err_msg)
