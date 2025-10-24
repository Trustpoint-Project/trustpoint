#!/bin/bash
# This script handles the transition from crypto storage setup to the next wizard state.
# Usage: wizard_setup_crypto_storage.sh <storage_type>

STATE_FILE_DIR="/etc/trustpoint/wizard/state/"
WIZARD_SETUP_CRYPTO_STORAGE="/etc/trustpoint/wizard/state/WIZARD_SETUP_CRYPTO_STORAGE"
WIZARD_SETUP_HSM="/etc/trustpoint/wizard/state/WIZARD_SETUP_HSM"
WIZARD_SETUP_MODE="/etc/trustpoint/wizard/state/WIZARD_SETUP_MODE"

# Parameters from view
STORAGE_TYPE="$1"

# Logging function
log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1"
}

# Check arguments
if [ $# -ne 1 ]; then
    echo "ERROR: Invalid number of arguments. Usage: $0 <storage_type>"
    exit 1
fi

if [ -z "$STORAGE_TYPE" ]; then
    echo "ERROR: Storage type must be provided. Usage: $0 <storage_type>"
    exit 1
fi

# Validate storage type
if [ "$STORAGE_TYPE" != "software" ] && [ "$STORAGE_TYPE" != "softhsm" ] && [ "$STORAGE_TYPE" != "physical_hsm" ]; then
    echo "ERROR: Invalid storage type '$STORAGE_TYPE'. Must be 'software', 'softhsm', or 'physical_hsm'."
    exit 5
fi

# Check if we're in the correct wizard state
if [ ! -f "$WIZARD_SETUP_CRYPTO_STORAGE" ]; then
    echo "ERROR: Trustpoint is not in the WIZARD_SETUP_CRYPTO_STORAGE state."
    exit 1
fi

# Check consistency - only one state file should be present
STATE_COUNT=$(find "$STATE_FILE_DIR" -maxdepth 1 -type f | wc -l)
if [[ 1 -ne STATE_COUNT ]]; then
    echo "ERROR: Found multiple wizard state files. The wizard state seems to be corrupted."
    exit 2
fi

log "Processing crypto storage configuration transition for storage type: $STORAGE_TYPE"

# Remove the current WIZARD_SETUP_CRYPTO_STORAGE state file
if ! rm "$WIZARD_SETUP_CRYPTO_STORAGE"; then
    echo "ERROR: Failed to remove the WIZARD_SETUP_CRYPTO_STORAGE state file."
    exit 3
fi

# Create the appropriate next state file based on storage type
if [ "$STORAGE_TYPE" = "software" ]; then
    # Software storage - go directly to setup mode
    if ! touch "$WIZARD_SETUP_MODE"; then
        echo "ERROR: Failed to create the WIZARD_SETUP_MODE state file."
        exit 4
    fi
    log "SUCCESS: Transitioned to WIZARD_SETUP_MODE state for software storage."
elif [ "$STORAGE_TYPE" = "softhsm" ] || [ "$STORAGE_TYPE" = "physical_hsm" ]; then
    # HSM storage - go to HSM setup
    if ! touch "$WIZARD_SETUP_HSM"; then
        echo "ERROR: Failed to create the WIZARD_SETUP_HSM state file."
        exit 4
    fi
    log "SUCCESS: Transitioned to WIZARD_SETUP_HSM state for HSM storage."
fi

log "Crypto storage setup transition completed successfully."
exit 0