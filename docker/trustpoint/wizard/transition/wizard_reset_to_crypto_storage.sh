#!/bin/bash
# This script resets the wizard state back to WIZARD_SETUP_CRYPTO_STORAGE.
# This is used when the wizard is incomplete and needs to restart from the beginning.
# Usage: wizard_reset_to_crypto_storage.sh

STATE_FILE_DIR="/etc/trustpoint/wizard/state/"
WIZARD_SETUP_CRYPTO_STORAGE="/etc/trustpoint/wizard/state/WIZARD_SETUP_CRYPTO_STORAGE"

# Logging function
log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1"
}

# Check if state directory exists
if [ ! -d "$STATE_FILE_DIR" ]; then
    echo "ERROR: Wizard state directory does not exist: $STATE_FILE_DIR"
    exit 1
fi

STATE_COUNT=$(ls -1 -A "$STATE_FILE_DIR" | wc -l)
if [[ 1 -ne STATE_COUNT ]]; then
    echo "Found multiple wizard state files. The wizard state seems to be corrupted."
    exit 2
fi

log "Resetting wizard state to WIZARD_SETUP_CRYPTO_STORAGE"

# Remove all existing wizard state files
log "Removing all existing wizard state files..."
find "$STATE_FILE_DIR" -maxdepth 1 -type f -name "WIZARD_*" -delete

# Create the WIZARD_SETUP_CRYPTO_STORAGE state file
log "Creating WIZARD_SETUP_CRYPTO_STORAGE state file..."
touch "$WIZARD_SETUP_CRYPTO_STORAGE"

if [ ! -f "$WIZARD_SETUP_CRYPTO_STORAGE" ]; then
    echo "ERROR: Failed to create WIZARD_SETUP_CRYPTO_STORAGE state file"
    exit 3
fi

log "Successfully reset wizard state to WIZARD_SETUP_CRYPTO_STORAGE"
exit 0
