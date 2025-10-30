#!/bin/bash
# This script will transition the from the WIZARD_INITIAL state to the WIZARD_TLS_SERVER_CREDENTIAL_APPLY state.

STATE_FILE_DIR="/etc/trustpoint/wizard/state/"
WIZARD_SETUP_MODE="/etc/trustpoint/wizard/state/WIZARD_SETUP_MODE"
WIZARD_TLS_SERVER_CREDENTIAL_APPLY="/etc/trustpoint/wizard/state/WIZARD_TLS_SERVER_CREDENTIAL_APPLY"

# Checks if the state file is present.
if [ ! -f "$WIZARD_SETUP_MODE" ]; then
    echo "ERROR: Trustpoint is not in the WIZARD_SETUP_MODE state. State file '$WIZARD_SETUP_MODE' not found."
    exit 1
fi

# Checks consistency, that is if only a single state file is present.
# TODO(AlexHx8472): Replace ls by find: SC2012
STATE_COUNT=$(ls -1 -A "$STATE_FILE_DIR" | wc -l)
if [[ 1 -ne STATE_COUNT ]]; then
    echo "ERROR: Found $STATE_COUNT state files in '$STATE_FILE_DIR'. Wizard state appears corrupted."
    exit 2
fi

# Removes the current WIZARD_SETUP_MODE state file.
if ! rm "$WIZARD_SETUP_MODE"
then
    echo "ERROR: Failed to remove the WIZARD_SETUP_MODE state file."
    exit 3
fi

# Creates the WIZARD_TLS_SERVER_CREDENTIAL_APPLY state file.
if ! touch "$WIZARD_TLS_SERVER_CREDENTIAL_APPLY"
then
    echo "ERROR: Failed to create the WIZARD_TLS_SERVER_CREDENTIAL_APPLY state file."
    exit 4
fi

echo "SUCCESS: Transitioned to WIZARD_TLS_SERVER_CREDENTIAL_APPLY state."
exit 0