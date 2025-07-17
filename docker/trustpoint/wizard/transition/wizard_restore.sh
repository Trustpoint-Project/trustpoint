#!/usr/bin/env bash

# 1) Pipe all output (stdout+stderr) into your trustpoint log and to the console
LOGFILE=/var/www/html/trustpoint/trustpoint/media/log/trustpoint.log
exec > >(tee -a "$LOGFILE") 2>&1

# 2) Exit on any error, and fail on pipe errors
set -eE -o pipefail

# 3) A simple log function matching your other logs
#    Usage: log LEVEL "your message…"
log() {
  local level=$1; shift
  printf '%s - wizard_restore.sh - %s - %s\n' \
    "$(date '+%Y-%m-%d %H:%M:%S')" \
    "$level" \
    "$*"
}

# 4) Trap unexpected errors and log them
trap 'log ERROR "in ${FUNCNAME[0]:-main} at line $LINENO (exit=$?)"; exit 1' ERR

# ————— Paths —————
STATE_DIR="/etc/trustpoint/wizard/state"
WIZARD_INITIAL="$STATE_DIR/WIZARD_INITIAL"
WIZARD_COMPLETED="$STATE_DIR/WIZARD_COMPLETED"
APACHE_TLS_DIR="/etc/trustpoint/tls"

log INFO "STARTING APACHE RESTORE"

# 5) Check wizard state
log INFO "Checking for state file $WIZARD_INITIAL"
if [ ! -f "$WIZARD_INITIAL" ]; then
  log ERROR "State file $WIZARD_INITIAL not found"
  exit 1
fi

# Removes the current WIZARD_INITIAL state file.
if ! rm "$WIZARD_INITIAL"
then
    log "ERROR: Failed to remove the WIZARD_INITIAL state file."
    exit 3
fi

# Creates the WIZARD_COMPLETED state file.
if ! touch "$WIZARD_COMPLETED"
then
    log "ERROR: Failed to create the WIZARD_COMPLETED state file."
    exit 4
fi

# configure tsl
/etc/trustpoint/wizard/transition/update_tls.sh

# 12) gracefully restart Apache if already running
if pgrep apache2 >/dev/null; then
   log INFO "Restarting Apache (graceful)"
   apache2ctl graceful
fi

log INFO "RESTORE SCRIPT COMPLETED SUCCESSFULLY"
exit 0
