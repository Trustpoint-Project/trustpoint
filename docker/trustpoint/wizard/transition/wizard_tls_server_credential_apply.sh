#!/bin/bash
# This script will transition from the WIZARD_TLS_SERVER_CREDENTIAL_APPLY state 
# to either WIZARD_BACKUP_PASSWORD (for HSM) or WIZARD_DEMO_DATA (for software storage).
# Usage: wizard_tls_server_credential_apply.sh [hsm|no_hsm]

STATE_FILE_DIR="/etc/trustpoint/wizard/state/"
WIZARD_TLS_SERVER_CREDENTIAL_APPLY="/etc/trustpoint/wizard/state/WIZARD_TLS_SERVER_CREDENTIAL_APPLY"
WIZARD_BACKUP_PASSWORD="/etc/trustpoint/wizard/state/WIZARD_BACKUP_PASSWORD"
WIZARD_DEMO_DATA="/etc/trustpoint/wizard/state/WIZARD_DEMO_DATA"

# Logging function
log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1"
}

# Check for required parameter
if [ $# -ne 1 ]; then
    echo "ERROR: Missing required parameter."
    echo "Usage: $0 [hsm|no_hsm]"
    exit 1
fi

STORAGE_MODE="$1"

# Validate parameter
if [[ "$STORAGE_MODE" != "hsm" && "$STORAGE_MODE" != "no_hsm" ]]; then
    echo "ERROR: Invalid parameter '$STORAGE_MODE'. Must be 'hsm' or 'no_hsm'."
    echo "Usage: $0 [hsm|no_hsm]"
    exit 1
fi

log "Processing TLS credential apply with storage mode: $STORAGE_MODE"

# Checks if the state file is present.
if [ ! -f "$WIZARD_TLS_SERVER_CREDENTIAL_APPLY" ]; then
    echo "ERROR: Trustpoint is not in the WIZARD_TLS_SERVER_CREDENTIAL_APPLY state. State file not found."
    exit 2
fi

# Checks consistency, that is if only a single state file is present.
STATE_COUNT=$(find "$STATE_FILE_DIR" -maxdepth 1 -type f | wc -l)
if [[ 1 -ne STATE_COUNT ]]; then
    echo "ERROR: Found $STATE_COUNT state files in $STATE_FILE_DIR. Wizard state seems to be corrupted."
    exit 3
fi

# Removes the current WIZARD_TLS_SERVER_CREDENTIAL_APPLY state file.
if ! rm "$WIZARD_TLS_SERVER_CREDENTIAL_APPLY"; then
    echo "ERROR: Failed to remove the WIZARD_TLS_SERVER_CREDENTIAL_APPLY state file."
    exit 4
fi

# Create the appropriate next state file based on storage mode
if [[ "$STORAGE_MODE" == "hsm" ]]; then
    log "HSM storage detected. Transitioning to WIZARD_BACKUP_PASSWORD state."
    if ! touch "$WIZARD_BACKUP_PASSWORD"; then
        echo "ERROR: Failed to create the WIZARD_BACKUP_PASSWORD state file."
        exit 5
    fi
    NEXT_STATE="WIZARD_BACKUP_PASSWORD"
else
    log "Software storage detected. Skipping backup password setup."
    if ! touch "$WIZARD_DEMO_DATA"; then
        echo "ERROR: Failed to create the WIZARD_DEMO_DATA state file."
        exit 6
    fi
    NEXT_STATE="WIZARD_DEMO_DATA"
fi

# Configure apache and TLS
log "Configuring Nginx and TLS..."
if ! /etc/trustpoint/wizard/transition/update_tls.sh; then
    echo "ERROR: Failed to configure Apache and TLS."
    exit 7
fi

echo "SUCCESS: Transition from WIZARD_TLS_SERVER_CREDENTIAL_APPLY to $NEXT_STATE completed successfully."
log "Transition completed successfully to $NEXT_STATE state."
exit 0