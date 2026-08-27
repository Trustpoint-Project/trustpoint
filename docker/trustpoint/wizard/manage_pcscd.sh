#!/usr/bin/env bash
set -euo pipefail

LOGFILE="/var/www/html/trustpoint/trustpoint/media/log/trustpoint.log"

log() {
    local level="$1"
    shift
    echo "$(date '+%Y-%m-%d %H:%M:%S') - manage_pcscd.sh - ${level} - $*" | tee -a "$LOGFILE"
}

start_pcscd() {
    mkdir -p /run/pcscd

    if pgrep -x pcscd >/dev/null 2>&1; then
        log INFO "pcscd is already running."
        return 0
    fi

    if [ ! -d /dev/bus/usb ]; then
        log ERROR "USB bus is not mounted at /dev/bus/usb."
        exit 2
    fi

    log INFO "Starting pcscd for USB smart-card HSM access."
    # The container has no polkit service, so pcscd must authorize clients through
    # the container boundary instead of desktop-session policy.
    pcscd --disable-polkit
    sleep 1

    if ! pgrep -x pcscd >/dev/null 2>&1; then
        log ERROR "pcscd did not stay running."
        exit 1
    fi

    log INFO "pcscd started successfully."
}

stop_pcscd() {
    if pgrep -x pcscd >/dev/null 2>&1; then
        log INFO "Stopping pcscd."
        pkill -x pcscd
    fi

    rm -f /run/pcscd/pcscd.comm /run/pcscd/pcscd.pid 2>/dev/null || true
    log INFO "pcscd stopped."
}

status_pcscd() {
    if pgrep -x pcscd >/dev/null 2>&1; then
        log INFO "pcscd is running."
        exit 0
    fi

    log INFO "pcscd is not running."
    exit 3
}

case "${1:-}" in
    start)
        start_pcscd
        ;;
    stop)
        stop_pcscd
        ;;
    status)
        status_pcscd
        ;;
    *)
        echo "Usage: $0 start|stop|status" >&2
        exit 64
        ;;
esac
