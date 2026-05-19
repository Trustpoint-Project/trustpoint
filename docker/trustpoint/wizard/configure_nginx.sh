#!/bin/bash
# Nginx base config (no TLS directory handling)

LOGFILE=/var/www/html/trustpoint/trustpoint/media/log/trustpoint.log
set -eE -o pipefail

log() {
    local level=$1; shift
    local message
    message="$(printf '%s - configure_nginx.sh - %s - %s\n' \
        "$(date '+%Y-%m-%d %H:%M:%S')" "$level" "$*")"
    echo "$message" | tee -a "$LOGFILE"
}

log INFO "Removing standard enabled Nginx sites"
rm -f /etc/nginx/sites-enabled/*

log INFO "Installing Nginx HTTPS config..."
cp /var/www/html/trustpoint/docker/trustpoint/nginx/trustpoint-nginx-https.conf \
   /etc/nginx/sites-available/trustpoint

log INFO "Enabling Nginx vhost..."
ln -sf /etc/nginx/sites-available/trustpoint /etc/nginx/sites-enabled/trustpoint

log INFO "Testing Nginx base configuration..."
if ! nginx -t; then
    log ERROR "Nginx configuration test failed."
    exit 9
fi

log INFO "Nginx configuration completed successfully"
