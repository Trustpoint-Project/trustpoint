#!/usr/bin/env bash

LOGFILE=/var/www/html/trustpoint/trustpoint/media/log/trustpoint.log

exec > >(tee -a "$LOGFILE") 2>&1

set -eE -o pipefail

log() {
    local level=$1; shift
    printf '%s - wizard_restore.sh - %s - %s\n' \
        "$(date '+%Y-%m-%d %H:%M:%S')" "$level" "$*"
}

trap 'log ERROR "in ${FUNCNAME[0]:-main} at line $LINENO (exit=$?)"; exit 1' ERR

STATE_DIR="/etc/trustpoint/wizard/state"
WIZARD_INITIAL="$STATE_DIR/WIZARD_INITIAL"
WIZARD_COMPLETED="$STATE_DIR/WIZARD_COMPLETED"

log INFO "STARTING NGINX RESTORE"

# DEBUG: Check what state files exist
log INFO "DEBUG: Checking state directory contents:"
ls -la "$STATE_DIR" || log ERROR "Cannot list state directory"

log INFO "Checking for state file $WIZARD_INITIAL"
if [ ! -f "$WIZARD_INITIAL" ]; then
    log ERROR "State file $WIZARD_INITIAL not found"
    exit 1
fi

log INFO "DEBUG: About to remove WIZARD_INITIAL"
if ! rm "$WIZARD_INITIAL"; then
    log ERROR "Failed to remove the WIZARD_INITIAL state file."
    exit 3
fi

log INFO "DEBUG: About to create WIZARD_COMPLETED"
if ! touch "$WIZARD_COMPLETED"; then
    log ERROR "Failed to create the WIZARD_COMPLETED state file."
    exit 4
fi

# If Nginx is running, update tls and reload
log INFO "DEBUG: Checking if nginx is running"
if pgrep nginx >/dev/null; then
    log INFO "DEBUG: Nginx is running, updating TLS"
    if [ -f "/etc/trustpoint/wizard/transition/update_tls_nginx.sh" ]; then
        /etc/trustpoint/wizard/transition/update_tls_nginx.sh
    fi
    log INFO "Reloading Nginx"
    nginx -s reload
else
    log INFO "DEBUG: Nginx is not running"
fi

log INFO "RESTORE SCRIPT COMPLETED SUCCESSFULLY"
exit 0
