#!/bin/bash
# Nginx TLS Configuration Script


NGINX_TLS_DIRECTORY="/etc/trustpoint/nginx/tls/"
LOGFILE=/var/www/html/trustpoint/trustpoint/media/log/trustpoint.log

#1) Exit on any error, and fail on pipe errors
set -eE -o pipefail

# 2)Log function matching your other logs
log() {
    local level=$1; shift
    local message
    message="$(printf '%s - configure_nginx.sh - %s - %s\n' \
        "$(date '+%Y-%m-%d %H:%M:%S')" "$level" "$*")"
    echo "$message" | tee -a "$LOGFILE"
}

# 3) Set proper permissions for nginx
log INFO "Setting proper file permissions for nginx TLS files"
chown -R www-data:www-data "$NGINX_TLS_DIRECTORY"
chmod 755 "$NGINX_TLS_DIRECTORY"
chmod 644 "${NGINX_TLS_DIRECTORY}"*.pem 2>/dev/null || true
chmod 600 "${NGINX_TLS_DIRECTORY}"*key*.pem 2>/dev/null || true

# 4) Verify files are in place
log INFO "Verifying TLS files are properly placed:"
ls -la "$NGINX_TLS_DIRECTORY" | while read -r line; do
    log INFO "  $line"
done
# 5) Test nginx configuration before restart
log INFO "Testing nginx configuration with new TLS certificates"
if ! nginx -t; then
    log ERROR "Nginx configuration test failed with new TLS certificates"
    exit 9
fi

# 6) Check if nginx is actually running (not just processes exist)
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
