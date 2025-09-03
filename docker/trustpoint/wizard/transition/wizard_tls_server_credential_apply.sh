#!/bin/bash
# This script will transition the from the WIZARD_INITIAL state to the WIZARD_TLS_SERVER_CREDENTIAL_APPLY state.

STATE_FILE_DIR="/etc/trustpoint/wizard/state/"
APACHE_TLS_DIRECTORY="/etc/trustpoint/tls/"
WIZARD_TLS_SERVER_CREDENTIAL_APPLY="/etc/trustpoint/wizard/state/WIZARD_TLS_SERVER_CREDENTIAL_APPLY"
WIZARD_DEMO_DATA="/etc/trustpoint/wizard/state/WIZARD_DEMO_DATA"

# Checks if the state file is present.
if [ ! -f "$WIZARD_TLS_SERVER_CREDENTIAL_APPLY" ]; then
    echo "ERROR: Trustpoint is not in the WIZARD_TLS_SERVER_CREDENTIAL_APPLY state. State file not found."
    exit 1
fi

# Checks consistency, that is if only a single state file is present.
# TODO(AlexHx8472): Replace ls by find: SC2012
STATE_COUNT=$(ls -1 -A "$STATE_FILE_DIR" | wc -l)
if [[ 1 -ne STATE_COUNT ]]; then
    echo "ERROR: Found $STATE_COUNT state files in $STATE_FILE_DIR. Wizard state seems to be corrupted."
    exit 2
fi

# Removes the current WIZARD_TLS_SERVER_CREDENTIAL_APPLY state file.
if ! rm "$WIZARD_TLS_SERVER_CREDENTIAL_APPLY"
then
    echo "ERROR: Failed to remove the WIZARD_TLS_SERVER_CREDENTIAL_APPLY state file."
    exit 14
fi

# Creates the WIZARD_DEMO_DATA state file.
if ! touch "$WIZARD_DEMO_DATA"
then
    echo "ERROR: Failed to create the WIZARD_DEMO_DATA state file."
    exit 15
fi

# configure apache and tsl
/etc/trustpoint/wizard/transition/update_tls_nginx.sh

echo "Transition from WIZARD_TLS_SERVER_CREDENTIAL_APPLY to WIZARD_DEMO_DATA completed successfully."
exit 0
