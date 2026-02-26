#!/bin/bash
# /etc/trustpoint/wizard/transition/update_tls_nginx.sh
NGINX_TLS_DIR="/etc/trustpoint/tls/"
LOGFILE=/var/www/html/trustpoint/trustpoint/media/log/trustpoint.log
MAX_RETRIES=3
DELAY=2  # seconds
RETRY_COUNT=0

set -eE -o pipefail


log() {
    local level=$1; shift
    echo "$(date '+%Y-%m-%d %H:%M:%S') - update_tls_nginx.sh - $level - $*" | tee -a "$LOGFILE"
}

log INFO "Starting TLS certificate setup for nginx"

# Create nginx TLS directory
mkdir -p "$NGINX_TLS_DIR"




# 2) Move new TLS certs
log INFO "Move TLS Server credentials into $NGINX_TLS_DIR"

# Copies the TLS-Server credentials into the nginx TLS directory.
if ! mv /var/www/html/trustpoint/docker/trustpoint/nginx/tls/* "$NGINX_TLS_DIR"
then
    log ERROR "Failed to copy Trustpoint TLS files to $NGINX_TLS_DIR."
    exit 5
fi


# Test nginx configuration with new certificates
log INFO "Testing nginx configuration with new TLS certificates"
if nginx -t; then
    log INFO "Nginx configuration test passed"
else
    log ERROR "Nginx configuration test failed"
    exit 2
fi

while [ $RETRY_COUNT -lt $MAX_RETRIES ]; do
    # Check if nginx is actually running (not just processes exist)
    if [ -f /run/nginx.pid ] && [ -s /run/nginx.pid ] && kill -0 "$(cat /run/nginx.pid)" 2>/dev/null; then
        log INFO "Nginx is running - reloading configuration (graceful)"
        if nginx -s reload; then
            log INFO "Nginx successfully reloaded with new TLS certificates"
            break
        else
            # Don't exit here since nginx will pick up config on next start
            log WARN "Failed to gracefully reload nginx configuration, retrying in $DELAY seconds..."
            sleep $DELAY
            RETRY_COUNT=$((RETRY_COUNT + 1))
        fi
    else
        log WARN "Nginx is not currently running, retrying in $DELAY seconds..."
        sleep $DELAY
        RETRY_COUNT=$((RETRY_COUNT + 1))
    fi
done
if [ $RETRY_COUNT -eq $MAX_RETRIES ]; then
    log ERROR "Failed to reload Nginx after $MAX_RETRIES attempts, TLS certificates will be applied on next start"
fi

sleep $DELAY
log INFO "TLS certificate update for nginx completed successfully"
