#!/bin/bash
# Nginx TLS Configuration Script
# Adapted from Apache version for nginx usage

NGINX_TLS_DIRECTORY="/etc/trustpoint/nginx/tls/"
LOGFILE=/var/www/html/trustpoint/trustpoint/media/log/trustpoint.log

# Exit on any error, and fail on pipe errors
set -eE -o pipefail

# Log function matching your other logs
log() {
    local level=$1; shift
    local message
    message="$(printf '%s - configure_nginx.sh - %s - %s\n' \
        "$(date '+%Y-%m-%d %H:%M:%S')" "$level" "$*")"
    echo "$message" | tee -a "$LOGFILE"
}

# 1) (Re-)create and clean nginx TLS directory
log INFO "Ensuring nginx TLS directory exists: $NGINX_TLS_DIRECTORY"
if ! mkdir -p "$NGINX_TLS_DIRECTORY"; then
    log ERROR "Failed to create the required nginx TLS directory at $NGINX_TLS_DIRECTORY."
    exit 3
fi

# Clear any existing TLS files in nginx directory
log INFO "Removing any existing old TLS files from $NGINX_TLS_DIRECTORY"
if ! rm -f "${NGINX_TLS_DIRECTORY}"*; then
    log ERROR "Failed to clear existing files in $NGINX_TLS_DIRECTORY."
    exit 4
fi

# 2) Copy TLS certs from apache directory to nginx directory
log INFO "Copying TLS Server credentials into $NGINX_TLS_DIRECTORY"

# Check if source apache TLS directory exists
APACHE_TLS_SOURCE="/var/www/html/trustpoint/docker/trustpoint/nginx/tls"
if [ ! -d "$APACHE_TLS_SOURCE" ]; then
    log ERROR "Source apache TLS directory not found: $APACHE_TLS_SOURCE"
    exit 6
fi

# Copy certificate files with proper naming for nginx
if [ -f "$APACHE_TLS_SOURCE/apache-tls-server-cert.pem" ]; then
    if ! cp "$APACHE_TLS_SOURCE/apache-tls-server-cert.pem" "${NGINX_TLS_DIRECTORY}apache-tls-server-cert.pem"; then
        log ERROR "Failed to copy TLS certificate to $NGINX_TLS_DIRECTORY"
        exit 5
    fi
else
    log ERROR "TLS certificate not found at $APACHE_TLS_SOURCE/apache-tls-server-cert.pem"
    exit 7
fi

if [ -f "$APACHE_TLS_SOURCE/apache-tls-server-key.key" ]; then
    if ! cp "$APACHE_TLS_SOURCE/apache-tls-server-key.key" "${NGINX_TLS_DIRECTORY}apache-tls-server-key.pem"; then
        log ERROR "Failed to copy TLS private key to $NGINX_TLS_DIRECTORY"
        exit 5
    fi
else
    log ERROR "TLS private key not found at $APACHE_TLS_SOURCE/apache-tls-server-key.key"
    exit 8
fi

# Copy certificate chain if it exists
if [ -f "$APACHE_TLS_SOURCE/apache-tls-server-cert-chain.pem" ]; then
    if ! cp "$APACHE_TLS_SOURCE/apache-tls-server-cert-chain.pem" "${NGINX_TLS_DIRECTORY}apache-tls-server-cert-chain.pem"; then
        log WARN "Failed to copy TLS certificate chain to $NGINX_TLS_DIRECTORY"
        # Don't exit on chain copy failure as it might not be required
    fi
fi

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

