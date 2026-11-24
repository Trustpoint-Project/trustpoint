#!/bin/bash
# Nginx base config (no TLS directory handling)

set -eE -o pipefail

# Keep privileged logging on stdout, away from application-writable paths.
log() {
    local level=$1; shift
    printf '%s - configure_nginx.sh - %s - %s\n' \
        "$(date '+%Y-%m-%d %H:%M:%S')" "$level" "$*"
}

log INFO "Removing standard enabled Nginx sites"
rm -f /etc/nginx/sites-enabled/*

log INFO "Installing Nginx HTTPS config..."
cp /var/www/html/trustpoint/docker/trustpoint/nginx/trustpoint-nginx-https.conf \
   /etc/nginx/sites-available/trustpoint

# Rootless deployments publish HTTPS on an unprivileged host port.
https_port="${TP_HTTPS_PORT:-443}"
if ! [[ "$https_port" =~ ^[0-9]{1,5}$ ]] || (( 10#$https_port < 1 || 10#$https_port > 65535 )); then
    log ERROR "Invalid HTTPS host port"
    exit 2
fi
if (( 10#$https_port != 443 )); then
    sed -i "s#https://\$host\$request_uri#https://\$host:${https_port}\$request_uri#" \
        /etc/nginx/sites-available/trustpoint
fi

log INFO "Enabling Nginx vhost..."
ln -sf /etc/nginx/sites-available/trustpoint /etc/nginx/sites-enabled/trustpoint

log INFO "Testing Nginx base configuration..."
if ! nginx -t; then
    log ERROR "Nginx configuration test failed."
    exit 9
fi

log INFO "Nginx configuration completed successfully"
