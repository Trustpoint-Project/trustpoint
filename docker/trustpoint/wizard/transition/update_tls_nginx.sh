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

# Check if certificates exist in apache directory and copy them
APACHE_TLS_DIR="/var/www/html/trustpoint/docker/trustpoint/nginx/tls"
NGINX_TLS_DIR="/etc/trustpoint/nginx/tls"

if [ -f "$APACHE_TLS_DIR/apache-tls-server-cert.pem" ]; then
    log INFO "Copying TLS certificates from apache to nginx directory"
    cp "$APACHE_TLS_DIR/apache-tls-server-cert.pem" "$NGINX_TLS_DIR/"
    cp "$APACHE_TLS_DIR/apache-tls-server-key.key" "$NGINX_TLS_DIR/apache-tls-server-key.pem"

    # Set proper permissions
    chown www-data:www-data "$NGINX_TLS_DIR"/*
    chmod 600 "$NGINX_TLS_DIR"/apache-tls-server-key.pem
    chmod 644 "$NGINX_TLS_DIR"/apache-tls-server-cert.pem

    log INFO "TLS certificates successfully prepared for nginx"
else
    log ERROR "TLS certificates not found in apache directory: $APACHE_TLS_DIR"
    log INFO "Available files in apache tls directory:"
    ls -la "$APACHE_TLS_DIR" || log ERROR "Apache TLS directory does not exist"
    exit 1
fi

# Verify certificates are now in place
if [ -f "$NGINX_TLS_DIR/apache-tls-server-cert.pem" ] && [ -f "$NGINX_TLS_DIR/apache-tls-server-key.pem" ]; then
    log INFO "TLS certificate verification successful"
    log INFO "Certificate files:"
    ls -la "$NGINX_TLS_DIR"
else
    log ERROR "TLS certificate verification failed"
    exit 1
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

