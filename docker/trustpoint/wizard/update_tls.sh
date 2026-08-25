#!/bin/bash
set -eE -o pipefail

NGINX_TLS_DIR="${TRUSTPOINT_NGINX_TLS_DIR:-/etc/trustpoint/tls}"
TLS_STAGING_DIR="${TRUSTPOINT_TLS_STAGING_DIR:-/var/www/html/trustpoint/docker/trustpoint/nginx/tls}"
LOGFILE="${TRUSTPOINT_LOG_FILE:-/var/www/html/trustpoint/trustpoint/media/log/trustpoint.log}"
NGINX_BIN="${TRUSTPOINT_NGINX_BIN:-nginx}"
MAX_RETRIES=3
DELAY=2
RETRY_COUNT=0

log() {
    local level=$1
    shift
    echo "$(date '+%Y-%m-%d %H:%M:%S') - update_tls.sh - $level - $*" | tee -a "$LOGFILE"
}

mkdir -p "$NGINX_TLS_DIR"

staged_key="$TLS_STAGING_DIR/nginx-tls-server-key.key"
staged_cert="$TLS_STAGING_DIR/nginx-tls-server-cert.pem"
staged_chain="$TLS_STAGING_DIR/nginx-tls-server-cert-chain.pem"
installed_key="$NGINX_TLS_DIR/nginx-tls-server-key.key"
installed_cert="$NGINX_TLS_DIR/nginx-tls-server-cert.pem"
installed_chain="$NGINX_TLS_DIR/nginx-tls-server-cert-chain.pem"

if [ -e "$staged_key" ] || [ -e "$staged_cert" ]; then
    if [ ! -f "$staged_key" ] || [ ! -f "$staged_cert" ]; then
        log ERROR "Staged TLS credential is incomplete; both private key and certificate are required."
        exit 5
    fi

    log INFO "Installing staged TLS credential into $NGINX_TLS_DIR"
    mv "$staged_key" "$installed_key"
    mv "$staged_cert" "$installed_cert"
    if [ -f "$staged_chain" ]; then
        mv "$staged_chain" "$installed_chain"
    fi
elif [ -f "$installed_key" ] && [ -f "$installed_cert" ]; then
    log INFO "No staged TLS credential found; using the installed credential"
else
    log ERROR "No complete staged or installed TLS credential is available."
    exit 5
fi

log INFO "Testing nginx configuration with TLS certificates"
if "$NGINX_BIN" -t; then
    log INFO "Nginx configuration test passed"
else
    log ERROR "Nginx configuration test failed"
    exit 2
fi

if [ -f /run/nginx.pid ] && [ -s /run/nginx.pid ] && kill -0 "$(cat /run/nginx.pid)" 2>/dev/null; then
    while [ "$RETRY_COUNT" -lt "$MAX_RETRIES" ]; do
        log INFO "Nginx is running - reloading configuration (graceful)"
        if "$NGINX_BIN" -s reload; then
            log INFO "Nginx successfully reloaded with new TLS certificates"
            break
        fi
        log WARN "Failed to gracefully reload nginx configuration, retrying in $DELAY seconds..."
        sleep "$DELAY"
        RETRY_COUNT=$((RETRY_COUNT + 1))
    done
    if [ "$RETRY_COUNT" -eq "$MAX_RETRIES" ]; then
        log ERROR "Failed to reload Nginx after $MAX_RETRIES attempts; certificates apply on next start"
    fi
    sleep "$DELAY"
else
    log INFO "Nginx is not running yet - certificates will be loaded on startup"
fi

log INFO "TLS certificate update for nginx completed successfully"
