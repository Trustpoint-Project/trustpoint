#!/bin/bash
# This script handles the backup password setup transition in the setup wizard.
# Usage: wizard_backup_password.sh

STATE_FILE_DIR="/etc/trustpoint/wizard/state/"
WIZARD_BACKUP_PASSWORD="/etc/trustpoint/wizard/state/WIZARD_BACKUP_PASSWORD"
WIZARD_TLS_SERVER_CREDENTIAL_APPLY="/etc/trustpoint/wizard/state/WIZARD_TLS_SERVER_CREDENTIAL_APPLY"

# Logging function
log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1"
}

# Check if we're in the correct state
if [ ! -f "$WIZARD_BACKUP_PASSWORD" ]; then
    echo "ERROR: Trustpoint is not in the WIZARD_BACKUP_PASSWORD state."
    exit 2
fi

# Check state consistency - only one state file should be present
STATE_COUNT=$(find "$STATE_FILE_DIR" -maxdepth 1 -type f | wc -l)
if [[ 1 -ne STATE_COUNT ]]; then
    echo "ERROR: Found multiple wizard state files. The wizard state seems to be corrupted."
    exit 3
fi

log "Processing backup password setup completion..."

# The actual backup password setting is handled by the Django view
# This script only handles the state transition

log "Backup password setup completed successfully."

# Remove the current WIZARD_BACKUP_PASSWORD state file
if ! rm "$WIZARD_BACKUP_PASSWORD"; then
    echo "ERROR: Failed to remove the WIZARD_BACKUP_PASSWORD state file."
    exit 4
fi

# Create the next state file
if ! touch "$WIZARD_TLS_SERVER_CREDENTIAL_APPLY"; then
    echo "ERROR: Failed to create the WIZARD_TLS_SERVER_CREDENTIAL_APPLY state file."
    exit 5
fi

echo "SUCCESS: Transitioned to WIZARD_TLS_SERVER_CREDENTIAL_APPLY state."

log "Backup password state transition completed successfully."
exit 0