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
WIZARD_SETUP_MODE="$STATE_DIR/WIZARD_SETUP_MODE"
WIZARD_COMPLETED="$STATE_DIR/WIZARD_COMPLETED"


log INFO "STARTING NGINX RESTORE"

# 5) Check wizard state
log INFO "Checking for state file $WIZARD_SETUP_MODE"
if [ ! -f "$WIZARD_SETUP_MODE" ]; then
  log ERROR "State file $WIZARD_SETUP_MODE not found"
  exit 1
fi

# Removes the current WIZARD_SETUP_MODE state file.
if ! rm "$WIZARD_SETUP_MODE"
then
    log "ERROR: Failed to remove the WIZARD_SETUP_MODE state file."
    exit 3
fi

# Creates the WIZARD_COMPLETED state file.
if ! touch "$WIZARD_COMPLETED"
then
    log "ERROR: Failed to create the WIZARD_COMPLETED state file."
    exit 4
fi

# 12) if Nginx is already running, update tls and gracefully restart
log INFO "DEBUG: Checking if nginx is running"
if pgrep nginx >/dev/null; then
    log INFO "DEBUG: Nginx is running, updating TLS"
    if [ -f "/etc/trustpoint/wizard/transition/update_tls.sh" ]; then
        /etc/trustpoint/wizard/transition/update_tls.sh
    fi
    log INFO "Reloading Nginx"
    nginx -s reload
else
    log INFO "DEBUG: Nginx is not running"
fi

log INFO "RESTORE SCRIPT COMPLETED SUCCESSFULLY"
exit 0
