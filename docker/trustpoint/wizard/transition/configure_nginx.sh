#!/bin/bash
LOGFILE=/var/www/html/trustpoint/trustpoint/media/log/trustpoint.log
set -eE -o pipefail

log() {
    local level=$1; shift
    echo "$(date '+%Y-%m-%d %H:%M:%S') - configure_nginx.sh - $level - $*" | tee -a "$LOGFILE"
}

log INFO "Starting Nginx configuration"

# Remove default nginx sites
rm -f /etc/nginx/sites-enabled/default 2>/dev/null || true
rm -f /etc/nginx/sites-enabled/trustpoint* 2>/dev/null || true

# Enable trustpoint site
if [ -f "/etc/nginx/sites-available/trustpoint" ]; then
    ln -sf /etc/nginx/sites-available/trustpoint /etc/nginx/sites-enabled/trustpoint
    log INFO "Enabled Trustpoint nginx site"
else
    log ERROR "Trustpoint nginx configuration not found"
    exit 8
fi

# Test nginx configuration
if nginx -t; then
    log INFO "Nginx configuration completed successfully"
else
    log ERROR "Nginx configuration test failed"
    exit 9
fi
