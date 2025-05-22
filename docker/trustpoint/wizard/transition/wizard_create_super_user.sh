#!/bin/bash
# This script will transition the from the WIZARD_CREATE_SUPER_USER state to the WIZARD_COMPLETED state.

STATE_FILE_DIR="/etc/trustpoint/wizard/state/"
WIZARD_CREATE_SUPER_USER="/etc/trustpoint/wizard/state/WIZARD_CREATE_SUPER_USER"
WIZARD_COMPLETED="/etc/trustpoint/wizard/state/WIZARD_COMPLETED"

# Checks if the state file is present.
if [ ! -f "$WIZARD_CREATE_SUPER_USER" ]; then
    echo "ERROR: Trustpoint is not in the WIZARD_CREATE_SUPER_USER state."
    exit 1
fi

# Checks consistency, that is if only a single state file is present.
# TODO(AlexHx8472): Replace ls by find: SC2012
STATE_COUNT=$(ls -1 -A "$STATE_FILE_DIR" | wc -l)
if [[ 1 -ne STATE_COUNT ]]; then
    echo "ERROR: Found multiple wizard state files. The wizard state seems to be corrupted."
    exit 2
fi

# Removes the current WIZARD_CREATE_SUPER_USER state file.
if ! rm "$WIZARD_CREATE_SUPER_USER"
then
    echo "ERROR: Failed to remove the WIZARD_CREATE_SUPER_USER state file."
    exit 3
fi

# Creates the WIZARD_COMPLETED state file.
if ! touch "$WIZARD_COMPLETED"
then
    echo "ERROR: Failed to create the WIZARD_COMPLETED state file."
    exit 4
fi

log "Wizard completed."
exit 0
