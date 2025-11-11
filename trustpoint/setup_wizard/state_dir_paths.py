"""Paths to state directory scripts used in the setup wizard."""

from pathlib import Path

# Define paths for wizard state scripts
STATE_FILE_DIR = Path('/etc/trustpoint/wizard/transition/')
SCRIPT_WIZARD_SETUP_CRYPTO_STORAGE = STATE_FILE_DIR / Path('wizard_setup_crypto_storage.sh')
SCRIPT_WIZARD_SETUP_HSM = STATE_FILE_DIR / Path('wizard_setup_hsm.sh')
SCRIPT_WIZARD_SETUP_MODE = STATE_FILE_DIR / Path('wizard_setup_mode.sh')
SCRIPT_WIZARD_SELECT_TLS_SERVER_CREDENTIAL = STATE_FILE_DIR / Path('wizard_select_tls_server_credential.sh')
SCRIPT_WIZARD_TLS_SERVER_CREDENTIAL_APPLY = STATE_FILE_DIR / Path('wizard_tls_server_credential_apply.sh')
SCRIPT_WIZARD_TLS_SERVER_CREDENTIAL_APPLY_CANCEL = STATE_FILE_DIR / Path('wizard_tls_server_credential_apply_cancel.sh')
SCRIPT_WIZARD_BACKUP_PASSWORD = STATE_FILE_DIR / Path('wizard_backup_password.sh')
SCRIPT_WIZARD_DEMO_DATA = STATE_FILE_DIR / Path('wizard_demo_data.sh')
SCRIPT_WIZARD_CREATE_SUPER_USER = STATE_FILE_DIR / Path('wizard_create_super_user.sh')
SCRIPT_WIZARD_RESTORE = STATE_FILE_DIR / Path('wizard_restore.sh')
SCRIPT_WIZARD_AUTO_RESTORE_SET = STATE_FILE_DIR / Path('wizard_auto_restore_set.sh')
SCRIPT_WIZARD_AUTO_RESTORE_SUCCESS = STATE_FILE_DIR / Path('wizard_auto_restore_success.sh')
SCRIPT_UPDATE_TLS_SERVER_CREDENTIAL = STATE_FILE_DIR / Path('update_tls.sh')
