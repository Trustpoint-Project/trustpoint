#!/bin/bash
# This script sets up an HSM slot using the pins provided via Docker Compose secrets.
# Usage: wizard_setup_hsm.sh <pkcs11_module_path> <slot_number> <token_label>

STATE_FILE_DIR="/etc/trustpoint/wizard/state/"
WIZARD_SETUP_HSM="/etc/trustpoint/wizard/state/WIZARD_SETUP_HSM"
WIZARD_TLS_SERVER_CREDENTIAL_APPLY="/etc/trustpoint/wizard/state/WIZARD_TLS_SERVER_CREDENTIAL_APPLY"

# HSM pin files from Docker Compose secrets
HSM_SO_PIN_FILE="${HSM_SO_PIN_FILE:-/run/secrets/hsm_so_pin}"
HSM_PIN_FILE="${HSM_PIN_FILE:-/run/secrets/hsm_pin}"

# Parameters from view
PKCS11_MODULE_PATH="$1"
HSM_SLOT="$2"
HSM_TOKEN_LABEL="$3"

# Logging function
log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1"
}

# Check arguments
if [ $# -ne 3 ]; then
    echo "ERROR: Invalid number of arguments. Usage: $0 <pkcs11_module_path> <slot_number> <token_label>"
    exit 1
fi

if [ -z "$PKCS11_MODULE_PATH" ] || [ -z "$HSM_SLOT" ] || [ -z "$HSM_TOKEN_LABEL" ]; then
    echo "ERROR: All arguments must be non-empty. Usage: $0 <pkcs11_module_path> <slot_number> <token_label>"
    exit 1
fi

# Checks if the state file is present.
if [ ! -f "$WIZARD_SETUP_HSM" ]; then
    echo "ERROR: Trustpoint is not in the WIZARD_SETUP_HSM state."
    exit 2
fi

# Checks consistency, that is if only a single state file is present.
STATE_COUNT=$(find "$STATE_FILE_DIR" -maxdepth 1 -type f | wc -l)
if [[ 1 -ne STATE_COUNT ]]; then
    echo "ERROR: Found multiple wizard state files. The wizard state seems to be corrupted."
    exit 3
fi

# Check if HSM pin files exist and are readable
if [ ! -r "$HSM_SO_PIN_FILE" ]; then
    echo "ERROR: HSM SO PIN file not found or not readable: $HSM_SO_PIN_FILE"
    exit 4
fi

if [ ! -r "$HSM_PIN_FILE" ]; then
    echo "ERROR: HSM PIN file not found or not readable: $HSM_PIN_FILE"
    exit 5
fi

# Read pins from files
HSM_SO_PIN=$(cat "$HSM_SO_PIN_FILE" 2>/dev/null)
HSM_PIN=$(cat "$HSM_PIN_FILE" 2>/dev/null)

if [ -z "$HSM_SO_PIN" ]; then
    echo "ERROR: HSM SO PIN is empty or could not be read from file."
    exit 6
fi

if [ -z "$HSM_PIN" ]; then
    echo "ERROR: HSM PIN is empty or could not be read from file."
    exit 7
fi

# Check if PKCS#11 module exists
if [ ! -f "$PKCS11_MODULE_PATH" ]; then
    echo "ERROR: PKCS#11 module not found: $PKCS11_MODULE_PATH"
    exit 8
fi

log "Initializing HSM slot $HSM_SLOT with token label '$HSM_TOKEN_LABEL' using module '$PKCS11_MODULE_PATH'..."

# Initialize the HSM slot
if ! softhsm2-util --init-token --module "$PKCS11_MODULE_PATH" --slot "$HSM_SLOT" --label "$HSM_TOKEN_LABEL" --pin "$HSM_PIN" --so-pin "$HSM_SO_PIN"; then
    echo "ERROR: Failed to initialize HSM token in slot $HSM_SLOT."
    exit 9
fi

log "HSM token initialized successfully."

# Test HSM access
log "Testing HSM access..."
if ! pkcs11-tool --module "$PKCS11_MODULE_PATH" --list-objects --pin "$HSM_PIN" >/dev/null 2>&1; then
    echo "ERROR: Failed to access HSM slot $HSM_SLOT with configured PIN."
    exit 11
fi

log "HSM access test successful."

# Removes the current WIZARD_SETUP_HSM state file.
if ! rm "$WIZARD_SETUP_HSM"
then
    echo "ERROR: Failed to remove the WIZARD_SETUP_HSM state file."
    exit 12
fi

if ! touch "$WIZARD_TLS_SERVER_CREDENTIAL_APPLY"
then
    echo "ERROR: Failed to create the WIZARD_TLS_SERVER_CREDENTIAL_APPLY state file."
    exit 13
fi

echo "SUCCESS: Transitioned to WIZARD_TLS_SERVER_CREDENTIAL_APPLY state."

log "HSM setup completed successfully."
exit 0