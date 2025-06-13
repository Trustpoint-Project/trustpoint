#!/bin/bash
# This script will transition the from the WIZARD_DEMO_DATA state to the WIZARD_CREATE_SUPER_USER state.

STATE_FILE_DIR="/etc/trustpoint/wizard/state/"
WIZARD_DEMO_DATA="/etc/trustpoint/wizard/state/WIZARD_DEMO_DATA"
WIZARD_CREATE_SUPER_USER="/etc/trustpoint/wizard/state/WIZARD_CREATE_SUPER_USER"

# Checks if the state file is present.
if [ ! -f "$WIZARD_DEMO_DATA" ]; then
    echo "Trustpoint is not in the WIZARD_INITIAL state."
    exit 1
fi

# Checks consistency, that is if only a single state file is present.
# TODO(AlexHx8472): Replace ls by find: SC2012
STATE_COUNT=$(ls -1 -A "$STATE_FILE_DIR" | wc -l)
if [[ 1 -ne STATE_COUNT ]]; then
    echo "Found multiple wizard state files. The wizard state seems to be corrupted."
    exit 2
fi

# Removes the current WIZARD_DEMO_DATA state file.
if ! rm "$WIZARD_DEMO_DATA"
then
    echo "Failed to remove the WIZARD_DEMO_DATA state file."
    exit 3
fi

# Creates the WIZARD_CREATE_SUPER_USER state file.
if ! touch "$WIZARD_CREATE_SUPER_USER"
then
    echo "Failed to create WIZARD_CREATE_SUPER_USER state file."
    exit 4
fi

log "Transition from WIZARD_DEMO_DATA to WIZARD_CREATE_SUPER_USER completed successfully."
exit 0