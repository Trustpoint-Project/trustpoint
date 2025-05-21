from __future__ import annotations

import enum
from pathlib import Path

WIZARD_STATE_PATH = Path('/etc/trustpoint/wizard/state')


class SetupWizardState(enum.Enum):
    WIZARD_INITIAL = WIZARD_STATE_PATH / Path('WIZARD_INITIAL')
    WIZARD_TLS_SERVER_CREDENTIAL_APPLY = WIZARD_STATE_PATH / Path('WIZARD_TLS_SERVER_CREDENTIAL_APPLY')
    WIZARD_DEMO_DATA = WIZARD_STATE_PATH / Path('WIZARD_DEMO_DATA')
    WIZARD_CREATE_SUPER_USER = WIZARD_STATE_PATH / Path('WIZARD_CREATE_SUPER_USER')
    WIZARD_COMPLETED = WIZARD_STATE_PATH / Path('WIZARD_COMPLETED')

    @classmethod
    def get_current_state(cls) -> SetupWizardState:
        for member in cls:
            if member.value.is_file():
                return member
        raise ValueError('Failed to determine wizard state.')
