#!/bin/bash
# This script will transition from the WIZARD_AUTO_RESTORE_PASSWORD state to the WIZARD_COMPLETED state.
# This is used when an automatic restore operation has completed successfully.

STATE_FILE_DIR="/etc/trustpoint/wizard/state/"
WIZARD_AUTO_RESTORE_PASSWORD="/etc/trustpoint/wizard/state/WIZARD_AUTO_RESTORE_PASSWORD"
WIZARD_COMPLETED="/etc/trustpoint/wizard/state/WIZARD_COMPLETED"

# Logging function
log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1"
}

# Checks if the state file is present.
if [ ! -f "$WIZARD_AUTO_RESTORE_PASSWORD" ]; then
    echo "ERROR: Trustpoint is not in the WIZARD_AUTO_RESTORE_PASSWORD state."
    exit 1
fi

# Checks consistency, that is if only a single state file is present.
STATE_COUNT=$(find "$STATE_FILE_DIR" -maxdepth 1 -type f | wc -l)
if [[ 1 -ne STATE_COUNT ]]; then
    echo "ERROR: Found multiple wizard state files. The wizard state seems to be corrupted."
    exit 2
fi

if ! rm "$WIZARD_AUTO_RESTORE_PASSWORD"
then
    echo "ERROR: Failed to remove the WIZARD_AUTO_RESTORE_PASSWORD state file."
    exit 3
fi

if ! touch "$WIZARD_COMPLETED"
then
    echo "ERROR: Failed to create the WIZARD_COMPLETED state file."
    exit 4
fi

log "Transitioned from WIZARD_AUTO_RESTORE_PASSWORD to WIZARD_COMPLETED state. Automatic restore operation completed."

log "Configuring Apache and TLS after successful auto restore..."

TRANSITION_DIR="/etc/trustpoint/wizard/transition"

# Configure Apache
if ! "$TRANSITION_DIR/configure_apache.sh"; then
    log "ERROR: Failed to configure Apache"
    exit 5
fi

# Configure TLS
if ! "$TRANSITION_DIR/update_tls.sh"; then
    log "ERROR: Failed to update TLS configuration"
    exit 6
fi

log "Apache and TLS configuration completed successfully"
exit 0