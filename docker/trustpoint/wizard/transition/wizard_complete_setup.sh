#!/usr/bin/env bash

# Script to complete wizard setup when DEK is accessible
# Transitions from any incomplete wizard state to WIZARD_COMPLETED

# 1) Pipe all output (stdout+stderr) into your trustpoint log and to the console
LOGFILE=/var/www/html/trustpoint/trustpoint/media/log/trustpoint.log
exec > >(tee -a "$LOGFILE") 2>&1

# 2) Exit on any error, and fail on pipe errors
set -eE -o pipefail

# 3) A simple log function matching your other logs
#    Usage: log LEVEL "your message…"
log() {
  local level=$1; shift
  printf '%s - wizard_complete_setup.sh - %s - %s\n' \
    "$(date '+%Y-%m-%d %H:%M:%S')" \
    "$level" \
    "$*"
}

# 4) Trap unexpected errors and log them
trap 'log ERROR "in ${FUNCNAME[0]:-main} at line $LINENO (exit=$?)"; exit 1' ERR

# ————— Paths —————
STATE_DIR="/etc/trustpoint/wizard/state"
WIZARD_COMPLETED="$STATE_DIR/WIZARD_COMPLETED"

log INFO "COMPLETING WIZARD SETUP"

# Remove any existing wizard state files
log INFO "Cleaning up existing wizard state files"
rm -f "$STATE_DIR"/WIZARD_*

# Create the WIZARD_COMPLETED state file
log INFO "Creating WIZARD_COMPLETED state file"
if ! touch "$WIZARD_COMPLETED"
then
    log ERROR "Failed to create the WIZARD_COMPLETED state file."
    exit 1
fi

log INFO "Wizard setup completed successfully"
exit 0
