#!/bin/bash
# This script will transition from the WIZARD_COMPLETED state to the WIZARD_AUTO_RESTORE state.
# This is used when an automatic restore operation is triggered.

STATE_FILE_DIR="/etc/trustpoint/wizard/state/"
WIZARD_COMPLETED="/etc/trustpoint/wizard/state/WIZARD_COMPLETED"
WIZARD_AUTO_RESTORE_HSM="/etc/trustpoint/wizard/state/WIZARD_AUTO_RESTORE_HSM"

# Logging function
log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1"
}

# Checks if the state file is present.
if [ ! -f "$WIZARD_COMPLETED" ]; then
    echo "ERROR: Trustpoint is not in the WIZARD_COMPLETED state."
    exit 1
fi

# Checks consistency, that is if only a single state file is present.
STATE_COUNT=$(find "$STATE_FILE_DIR" -maxdepth 1 -type f | wc -l)
if [[ 1 -ne STATE_COUNT ]]; then
    echo "ERROR: Found multiple wizard state files. The wizard state seems to be corrupted."
    exit 2
fi

# Removes the current WIZARD_COMPLETED state file.
if ! rm "$WIZARD_COMPLETED"
then
    echo "ERROR: Failed to remove the WIZARD_COMPLETED state file."
    exit 3
fi

# Creates the WIZARD_AUTO_RESTORE_HSM state file.
if ! touch "$WIZARD_AUTO_RESTORE_HSM"
then
    echo "ERROR: Failed to create the WIZARD_AUTO_RESTORE_HSM state file."
    exit 4
fi

log "Transitioned to WIZARD_AUTO_RESTORE_HSM state for automatic restore operation."
exit 0