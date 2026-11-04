#!/bin/bash
NGINX_TLS_DIR="/etc/trustpoint/tls/"
MAX_RETRIES=3
DELAY=2  # seconds
RETRY_COUNT=0

set -eE -o pipefail


log() {
    local level=$1; shift
    echo "$(date '+%Y-%m-%d %H:%M:%S') - update_tls_nginx.sh - $level - $*"
}

log INFO "Starting TLS certificate setup for nginx"

# Create nginx TLS directory
mkdir -p "$NGINX_TLS_DIR"

# Keep the previous files until Nginx accepts the update.
backup_dir=$(mktemp -d)
tls_files=(nginx-tls-server-key.key nginx-tls-server-cert.pem nginx-tls-server-cert-chain.pem)
for name in "${tls_files[@]}"; do
    if [ -f "$NGINX_TLS_DIR/$name" ]; then
        cp -p "$NGINX_TLS_DIR/$name" "$backup_dir/$name"
    fi
done
restore_tls() {
    local status=$?
    if [ "$status" -ne 0 ]; then
        for name in "${tls_files[@]}"; do
            rm -f "$NGINX_TLS_DIR/$name"
            if [ -f "$backup_dir/$name" ]; then
                cp -p "$backup_dir/$name" "$NGINX_TLS_DIR/$name"
            fi
        done
    fi
    rm -rf "$backup_dir"
    exit "$status"
}
trap restore_tls EXIT

staging_dir=/var/www/html/trustpoint/docker/trustpoint/nginx/tls
install -m 600 "$staging_dir/nginx-tls-server-key.key" "$NGINX_TLS_DIR/nginx-tls-server-key.key"
install -m 644 "$staging_dir/nginx-tls-server-cert.pem" "$NGINX_TLS_DIR/nginx-tls-server-cert.pem"
if [ -f "$staging_dir/nginx-tls-server-cert-chain.pem" ]; then
    install -m 644 "$staging_dir/nginx-tls-server-cert-chain.pem" "$NGINX_TLS_DIR/nginx-tls-server-cert-chain.pem"
else
    rm -f "$NGINX_TLS_DIR/nginx-tls-server-cert-chain.pem"
fi

# Test nginx configuration with new certificates
log INFO "Testing nginx configuration with new TLS certificates"
if nginx -t; then
    log INFO "Nginx configuration test passed"
else
    log ERROR "Nginx configuration test failed"
    exit 2
fi


if [ -f /run/nginx.pid ] && [ -s /run/nginx.pid ] && kill -0 "$(cat /run/nginx.pid)" 2>/dev/null; then
    while [ $RETRY_COUNT -lt $MAX_RETRIES ]; do
        log INFO "Nginx is running - reloading configuration (graceful)"
        if nginx -s reload; then
            log INFO "Nginx successfully reloaded with new TLS certificates"
            break
        else
            log WARN "Failed to gracefully reload nginx configuration, retrying in $DELAY seconds..."
            sleep $DELAY
            RETRY_COUNT=$((RETRY_COUNT + 1))
        fi
    done
    if [ $RETRY_COUNT -eq $MAX_RETRIES ]; then
        log ERROR "Failed to reload Nginx after $MAX_RETRIES attempts"
        exit 3
    fi
    sleep $DELAY
else
    log INFO "Nginx is not running yet - skipping reload, certificates will be loaded on startup"
fi
log INFO "TLS certificate update for nginx completed successfully"
