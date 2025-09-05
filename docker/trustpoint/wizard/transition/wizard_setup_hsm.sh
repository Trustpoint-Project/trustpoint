#!/bin/bash
# This script sets up an HSM slot using the pins provided via Docker Compose secrets.
# Usage: wizard_setup_hsm.sh <pkcs11_module_path> <slot_number> <token_label> [init_setup|auto_restore_setup]

STATE_FILE_DIR="/etc/trustpoint/wizard/state/"
WIZARD_SETUP_HSM="/etc/trustpoint/wizard/state/WIZARD_SETUP_HSM"
WIZARD_SETUP_MODE="/etc/trustpoint/wizard/state/WIZARD_SETUP_MODE"
WIZARD_AUTO_RESTORE_PASSWORD="/etc/trustpoint/wizard/state/WIZARD_AUTO_RESTORE_PASSWORD"

# HSM pin files from Docker Compose secrets
HSM_SO_PIN_FILE="${HSM_SO_PIN_FILE:-/run/secrets/hsm_so_pin}"
HSM_PIN_FILE="${HSM_PIN_FILE:-/run/secrets/hsm_pin}"

# Parameters from view
PKCS11_MODULE_PATH="$1"
HSM_SLOT="$2"
HSM_TOKEN_LABEL="$3"
SETUP_TYPE="$4"  # New parameter: init_setup or auto_restore_setup

# Logging function
log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1"
}

# Check arguments
if [ $# -lt 3 ] || [ $# -gt 4 ]; then
    echo "ERROR: Invalid number of arguments. Usage: $0 <pkcs11_module_path> <slot_number> <token_label> [init_setup|auto_restore_setup]"
    exit 1
fi

if [ -z "$PKCS11_MODULE_PATH" ] || [ -z "$HSM_SLOT" ] || [ -z "$HSM_TOKEN_LABEL" ]; then
    echo "ERROR: All arguments must be non-empty. Usage: $0 <pkcs11_module_path> <slot_number> <token_label> [init_setup|auto_restore_setup]"
    exit 1
fi

# Validate setup type if provided
if [ -n "$SETUP_TYPE" ] && [ "$SETUP_TYPE" != "init_setup" ] && [ "$SETUP_TYPE" != "auto_restore_setup" ]; then
    echo "ERROR: Invalid setup type. Must be 'init_setup' or 'auto_restore_setup'."
    exit 1
fi

# Default to init_setup if not specified
if [ -z "$SETUP_TYPE" ]; then
    SETUP_TYPE="init_setup"
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

log "Initializing HSM slot $HSM_SLOT with token label '$HSM_TOKEN_LABEL' using module '$PKCS11_MODULE_PATH' for setup type '$SETUP_TYPE'..."

# Initialize the HSM slot
if ! softhsm2-util --init-token --module "$PKCS11_MODULE_PATH" --slot "$HSM_SLOT" --label "$HSM_TOKEN_LABEL" --pin "$HSM_PIN" --so-pin "$HSM_SO_PIN"; then
    echo "ERROR: Failed to initialize HSM token in slot $HSM_SLOT."
    exit 9
fi

log "HSM token initialized successfully."

log "Setting correct permissions for SoftHSM files..."

# Add www-data to softhsm group (in case it's not already)
usermod -a -G softhsm www-data || log "WARNING: Could not add www-data to softhsm group"

if ! chgrp www-data /var/lib/softhsm; then
    log "WARNING: Failed to change group ownership of /var/lib/softhsm"
fi

if ! chmod 755 /var/lib/softhsm; then
    echo "ERROR: Failed to set permissions on /var/lib/softhsm directory."
    exit 17
fi

# Fix ownership and permissions of the entire SoftHSM directory structure
if ! chown -R www-data:www-data /var/lib/softhsm/tokens/; then
    echo "ERROR: Failed to set ownership of SoftHSM tokens to www-data."
    exit 14
fi

if ! chmod -R 755 /var/lib/softhsm/tokens/; then
    echo "ERROR: Failed to set permissions on SoftHSM tokens."
    exit 15
fi

# Ensure the SoftHSM config is readable by www-data
if ! chmod 644 /etc/softhsm2.conf; then
    echo "ERROR: Failed to set permissions on SoftHSM config file."
    exit 16
fi

log "DEBUG: Testing www-data access to token directory:"
if su -s /bin/bash www-data -c "ls /var/lib/softhsm/tokens/" >/dev/null 2>&1; then
    log "DEBUG: www-data can access token directory"
else
    log "ERROR: www-data still cannot access token directory"
    exit 18
fi

log "SoftHSM permissions set successfully."

# Test HSM access with proper environment
log "Testing HSM access as www-data user..."
if ! su -s /bin/bash www-data -c "SOFTHSM2_CONF=/etc/softhsm2.conf pkcs11-tool --module '$PKCS11_MODULE_PATH' --list-objects --pin '$HSM_PIN'" >/dev/null 2>&1; then
    echo "ERROR: Failed to access HSM slot $HSM_SLOT as www-data user."
    exit 19
fi

log "HSM access test successful."

# Removes the current WIZARD_SETUP_HSM state file.
if ! rm "$WIZARD_SETUP_HSM"
then
    echo "ERROR: Failed to remove the WIZARD_SETUP_HSM state file."
    exit 12
fi

# Create the appropriate next state file based on setup type
if [ "$SETUP_TYPE" = "init_setup" ]; then
    if ! touch "$WIZARD_SETUP_MODE"
    then
        echo "ERROR: Failed to create the WIZARD_SETUP_MODE state file."
        exit 13
    fi
    log "SUCCESS: Transitioned to WIZARD_SETUP_MODE state for initial setup."
elif [ "$SETUP_TYPE" = "auto_restore_setup" ]; then
    if ! touch "$WIZARD_AUTO_RESTORE_PASSWORD"
    then
        echo "ERROR: Failed to create the WIZARD_AUTO_RESTORE_PASSWORD state file."
        exit 20
    fi
    log "SUCCESS: Transitioned to WIZARD_AUTO_RESTORE_PASSWORD state for auto restore setup."
fi

log "HSM setup completed successfully."
exit 0