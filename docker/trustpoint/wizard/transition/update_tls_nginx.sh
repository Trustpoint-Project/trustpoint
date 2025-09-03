#!/bin/bash
NGINX_TLS_DIRECTORY="/etc/trustpoint/tls/"
LOGFILE=/var/www/html/trustpoint/trustpoint/media/log/trustpoint.log
set -eE -o pipefail

log() {
    local level=$1; shift
    echo "$(date '+%Y-%m-%d %H:%M:%S') - update_tls_nginx.sh - $level - $*" | tee -a "$LOGFILE"
}

# Create TLS directory
mkdir -p "$NGINX_TLS_DIRECTORY"

# Clean old TLS files
rm -f /etc/trustpoint/tls/* 2>/dev/null || true

# Copy TLS certs from apache directory (for migration)
if ls /var/www/html/trustpoint/docker/trustpoint/apache/tls/* 1> /dev/null 2>&1; then
    cp /var/www/html/trustpoint/docker/trustpoint/apache/tls/* "$NGINX_TLS_DIRECTORY"
    log INFO "TLS certificates copied from apache directory"
fi

# Set permissions
chmod 600 "$NGINX_TLS_DIRECTORY"/*.key 2>/dev/null || true
chmod 644 "$NGINX_TLS_DIRECTORY"/*.pem 2>/dev/null || true

# Reload nginx if running
if pgrep nginx >/dev/null; then
    nginx -s reload
    log INFO "Nginx reloaded"
fi

log INFO "TLS configuration updated successfully"
