#!/bin/bash
set -eE -o pipefail

LOG_DIR="/var/log/trustpoint"
: "${OPERATIONAL_ENV_FILE:?Validated handoff path is required}"
OPERATIONAL_PORT="${TRUSTPOINT_OPERATIONAL_GUNICORN_PORT:-8001}"
BOOTSTRAP_PORT="${TRUSTPOINT_BOOTSTRAP_GUNICORN_PORT:-8000}"
NGINX_SITE="/etc/nginx/sites-available/trustpoint"
OPERATIONAL_GUNICORN_PID_FILE="/run/trustpoint-operational-gunicorn.pid"
OPERATIONAL_QCLUSTER_PID_FILE="/run/trustpoint-operational-qcluster.pid"
UV_CACHE_DIR="${UV_CACHE_DIR:-/tmp/trustpoint-uv-cache}"
UV_NO_CACHE="${UV_NO_CACHE:-1}"
WWW_DATA_HOME="${WWW_DATA_HOME:-/tmp/trustpoint-www-data-home}"

log() {
    local level=$1; shift
    local message
    message="$(printf '%s - switch_to_operational.sh - %s - %s\n' \
        "$(date '+%Y-%m-%d %H:%M:%S')" "$level" "$*")"
    printf '%s\n' "$message"
}

if [ ! -f "$OPERATIONAL_ENV_FILE" ]; then
    log ERROR "Operational environment file not found: $OPERATIONAL_ENV_FILE"
    exit 2
fi

mkdir -p "$LOG_DIR"
chown root:root "$LOG_DIR"
chmod 755 "$LOG_DIR"
mkdir -p "$UV_CACHE_DIR" "$WWW_DATA_HOME"
chown www-data:www-data "$UV_CACHE_DIR" "$WWW_DATA_HOME"

export TRUSTPOINT_PHASE="operational"
export DJANGO_SETTINGS_MODULE="trustpoint.settings"
export UV_CACHE_DIR
export UV_NO_CACHE

if [ -n "${PKCS11_PROXY_SOCKET:-}" ]; then
    log INFO "Using PKCS#11 proxy socket ${PKCS11_PROXY_SOCKET}"
fi
if [ -n "${SOFTHSM2_CONF:-}" ]; then
    log INFO "Using SoftHSM config ${SOFTHSM2_CONF}"
fi

pid_file_alive() {
    local pid_file=$1
    [ -s "$pid_file" ] && kill -0 "$(cat "$pid_file")" 2>/dev/null
}

run_as_www_data() {
    /usr/local/bin/python3 -I /etc/trustpoint/runtime_config.py app "$1"
}

wait_for_postgres() {
    local attempt=1
    local max_attempts=30

    log INFO "Checking configured PostgreSQL availability as www-data"
    until run_as_www_data db-ready >/dev/null 2>&1; do
        if [ "$attempt" -ge "$max_attempts" ]; then
            log ERROR "PostgreSQL did not become available after $max_attempts attempts"
            exit 4
        fi
        attempt=$((attempt + 1))
        sleep 1
    done
}

run_auto_setup() {
    log INFO "Auto-setup marker detected, running auto-setup from environment..."
    run_as_www_data migrate
    run_as_www_data auto-setup
    rm -f /var/lib/trustpoint/bootstrap/auto-setup.marker
    log INFO "Auto-setup completed and marker removed"
}

run_startup_manager() {
    log INFO "Running operational startup manager"
    run_as_www_data startup
}

apply_operational_tls_files() {
    log INFO "Applying operational TLS files to nginx"
    /etc/trustpoint/wizard/update_tls.sh
}

start_qcluster() {
    if pid_file_alive "$OPERATIONAL_QCLUSTER_PID_FILE"; then
        log INFO "Operational qcluster is already running with PID $(cat "$OPERATIONAL_QCLUSTER_PID_FILE")"
        return
    fi

    log INFO "Starting operational Django-Q2 qcluster"
    run_as_www_data qcluster > "$LOG_DIR/qcluster.log" 2>&1 &
    local qcluster_pid=$!
    echo "$qcluster_pid" > "$OPERATIONAL_QCLUSTER_PID_FILE"

    sleep 3
    if ! kill -0 "$qcluster_pid" 2>/dev/null; then
        log ERROR "Operational qcluster failed to start. Check $LOG_DIR/qcluster.log"
        cat "$LOG_DIR/qcluster.log"
        exit 5
    fi
    log INFO "Operational qcluster started with PID $qcluster_pid"
}

start_operational_gunicorn() {
    if pid_file_alive "$OPERATIONAL_GUNICORN_PID_FILE"; then
        log INFO "Operational Gunicorn is already running with PID $(cat "$OPERATIONAL_GUNICORN_PID_FILE")"
        return
    fi

    log INFO "Starting operational Gunicorn on port $OPERATIONAL_PORT"
    run_as_www_data gunicorn > "$LOG_DIR/gunicorn-operational.log" 2>&1 &
    local gunicorn_pid=$!
    echo "$gunicorn_pid" > "$OPERATIONAL_GUNICORN_PID_FILE"

    sleep 2
    if ! kill -0 "$gunicorn_pid" 2>/dev/null; then
        log ERROR "Operational Gunicorn failed to start. Check $LOG_DIR/gunicorn-operational.log"
        cat "$LOG_DIR/gunicorn-operational.log"
        exit 6
    fi
    log INFO "Operational Gunicorn started with PID $gunicorn_pid"
}

wait_for_operational_http() {
    local attempt=1
    local max_attempts=30
    local health_url="http://127.0.0.1:${OPERATIONAL_PORT}/"

    log INFO "Checking operational HTTP availability at $health_url"
    until curl -fsS --max-time 2 "$health_url" >/dev/null 2>&1; do
        if [ "$attempt" -ge "$max_attempts" ]; then
            log ERROR "Operational Gunicorn did not answer HTTP after $max_attempts attempts."
            if [ -f "$LOG_DIR/gunicorn-operational.log" ]; then
                log ERROR "Last operational Gunicorn log lines:"
                tail -n 80 "$LOG_DIR/gunicorn-operational.log"
            fi
            exit 10
        fi
        attempt=$((attempt + 1))
        sleep 1
    done
    log INFO "Operational HTTP endpoint is reachable"
}

switch_nginx_proxy() {
    if [ ! -f "$NGINX_SITE" ]; then
        log ERROR "Nginx site config not found: $NGINX_SITE"
        exit 7
    fi

    if ! grep -Eq 'proxy_pass http://127\.0\.0\.1:[0-9]+;' "$NGINX_SITE"; then
        log ERROR "Could not find the Trustpoint proxy_pass line in $NGINX_SITE"
        exit 8
    fi

    log INFO "Switching nginx upstream to operational Gunicorn on port $OPERATIONAL_PORT"
    sed -i -E "s#proxy_pass http://127\.0\.0\.1:[0-9]+;#proxy_pass http://127.0.0.1:${OPERATIONAL_PORT};#" "$NGINX_SITE"

    if ! nginx -t; then
        log ERROR "Nginx rejected the operational proxy configuration"
        sed -i -E "s#proxy_pass http://127\.0\.0\.1:[0-9]+;#proxy_pass http://127.0.0.1:${BOOTSTRAP_PORT};#" "$NGINX_SITE"
        nginx -t >/dev/null 2>&1 || true
        exit 9
    fi

    if [ -f /run/nginx.pid ] && [ -s /run/nginx.pid ] && kill -0 "$(cat /run/nginx.pid)" 2>/dev/null; then
        nginx -s reload
        log INFO "Nginx reloaded on operational runtime"
    else
        log INFO "Nginx is not running; operational proxy config will be used on next nginx start"
    fi
}

schedule_bootstrap_gunicorn_shutdown() {
    log INFO "Scheduling bootstrap Gunicorn shutdown on port $BOOTSTRAP_PORT"
    nohup bash -c "sleep 10; ps -eo pid=,args= | awk '/gunicorn/ && /0\\.0\\.0\\.0:${BOOTSTRAP_PORT}/ && !/awk/ {print \$1}' | xargs -r kill -TERM" >/dev/null 2>&1 &
}

wait_for_postgres
if [ -f /var/lib/trustpoint/bootstrap/auto-setup.marker ]; then
    # auto_setup_from_env installs and reloads TLS itself, consuming staged files.
    run_auto_setup
else
    run_startup_manager
    apply_operational_tls_files
fi
start_qcluster
start_operational_gunicorn
wait_for_operational_http
switch_nginx_proxy
schedule_bootstrap_gunicorn_shutdown

log INFO "Trustpoint runtime switched to operational mode without container restart"
