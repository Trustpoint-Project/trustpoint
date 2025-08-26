#!/bin/bash
# This script will transition the from the WIZARD_INITIAL state to the WIZARD_TLS_SERVER_CREDENTIAL_APPLY state.

STATE_FILE_DIR="/etc/trustpoint/wizard/state/"
WIZARD_INITIAL="/etc/trustpoint/wizard/state/WIZARD_INITIAL"
WIZARD_SETUP_HSM="/etc/trustpoint/wizard/state/WIZARD_SETUP_HSM"

# Checks if the state file is present.
if [ ! -f "$WIZARD_INITIAL" ]; then
    echo "ERROR: Trustpoint is not in the WIZARD_INITIAL state. State file '$WIZARD_INITIAL' not found."
    exit 1
fi

# Checks consistency, that is if only a single state file is present.
# TODO(AlexHx8472): Replace ls by find: SC2012
STATE_COUNT=$(ls -1 -A "$STATE_FILE_DIR" | wc -l)
if [[ 1 -ne STATE_COUNT ]]; then
    echo "ERROR: Found $STATE_COUNT state files in '$STATE_FILE_DIR'. Wizard state appears corrupted."
    exit 2
fi

# Removes the current WIZARD_INITIAL state file.
if ! rm "$WIZARD_INITIAL"
then
    echo "ERROR: Failed to remove the WIZARD_INITIAL state file."
    exit 3
fi

# Creates the WIZARD_SETUP_HSM state file.
if ! touch "$WIZARD_SETUP_HSM"
then
    echo "ERROR: Failed to create the WIZARD_SETUP_HSM state file."
    exit 4
fi

echo "SUCCESS: Transitioned to WIZARD_HSM_CONFIGURED state."
exit 0