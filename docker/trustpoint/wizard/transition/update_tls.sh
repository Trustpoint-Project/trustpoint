#!/bin/bash
# /etc/trustpoint/wizard/transition/update_tls_nginx.sh

LOGFILE=/var/www/html/trustpoint/trustpoint/media/log/trustpoint.log

log() {
    local level=$1; shift
    echo "$(date '+%Y-%m-%d %H:%M:%S') - update_tls_nginx.sh - $level - $*" | tee -a "$LOGFILE"
}

log INFO "Starting TLS certificate setup for nginx"

# Create nginx TLS directory
mkdir -p /etc/trustpoint/nginx/tls/

# Check if certificates exist in nginx directory and copy them
NGINX_TLS_DIR="/etc/trustpoint/nginx/tls"

# 2) Move new TLS certs
log INFO "Move TLS Server credentials into $NGINX_TLS_DIR"

# Copies the TLS-Server credentials into the nginx TLS directory.
if ! mv /var/www/html/trustpoint/docker/trustpoint/nginx/tls/* "$NGINX_TLS_DIR"
then
    log "ERROR: Failed to copy Trustpoint TLS files to $NGINX_TLS_DIR."
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

# Check if nginx is actually running (not just processes exist)
if [ -f /run/nginx.pid ] && [ -s /run/nginx.pid ] && kill -0 "$(cat /run/nginx.pid)" 2>/dev/null; then
    log INFO "Nginx is running - reloading configuration (graceful)"
    if nginx -s reload; then
        log INFO "Nginx successfully reloaded with new TLS certificates"
    else
        log WARN "Failed to gracefully reload nginx configuration, but continuing"
        # Don't exit here since nginx will pick up config on next start
    fi
else
    log INFO "Nginx is not currently running - configuration will be applied on next start"
fi

log INFO "TLS certificate update for nginx completed successfully"
