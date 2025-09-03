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

log INFO "Checking for state file $WIZARD_INITIAL"
if [ ! -f "$WIZARD_INITIAL" ]; then
    log ERROR "State file $WIZARD_INITIAL not found"
    exit 1
fi

if ! rm "$WIZARD_INITIAL"; then
    log "ERROR: Failed to remove the WIZARD_INITIAL state file."
    exit 3
fi

if ! touch "$WIZARD_COMPLETED"; then
    log "ERROR: Failed to create the WIZARD_COMPLETED state file."
    exit 4
fi

# If Nginx is running, update tls and reload (instead of Apache commands)
if pgrep nginx >/dev/null; then
    if [ -f "/etc/trustpoint/wizard/transition/update_tls_nginx.sh" ]; then
        /etc/trustpoint/wizard/transition/update_tls_nginx.sh
    fi
    log INFO "Reloading Nginx"
    nginx -s reload
fi

log INFO "RESTORE SCRIPT COMPLETED SUCCESSFULLY"
exit 0
