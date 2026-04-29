#!/bin/bash
set -eE -o pipefail

APP_DIR="/var/www/html/trustpoint"
DJANGO_APP_DIR="$APP_DIR/trustpoint"
LOG_DIR="/var/log/trustpoint"
TRUSTPOINT_LOG="$APP_DIR/trustpoint/media/log/trustpoint.log"
OPERATIONAL_ENV_FILE="${1:-${TRUSTPOINT_OPERATIONAL_ENV_FILE:-/var/lib/trustpoint/bootstrap/operational.env}}"
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
    echo "$message" | tee -a "$TRUSTPOINT_LOG"
}

if [ ! -f "$OPERATIONAL_ENV_FILE" ]; then
    log ERROR "Operational environment file not found: $OPERATIONAL_ENV_FILE"
    exit 2
fi

mkdir -p "$LOG_DIR"
chown www-data:www-data "$LOG_DIR"
mkdir -p "$UV_CACHE_DIR" "$WWW_DATA_HOME"
chown -R www-data:www-data "$UV_CACHE_DIR" "$WWW_DATA_HOME"

set -a
# shellcheck disable=SC1090
. "$OPERATIONAL_ENV_FILE"
set +a
export TRUSTPOINT_PHASE="operational"
export DJANGO_SETTINGS_MODULE="trustpoint.settings"
export UV_CACHE_DIR
export UV_NO_CACHE
export HOME="$WWW_DATA_HOME"

if [ -n "${PKCS11_PROXY_SOCKET:-}" ]; then
    log INFO "Using PKCS#11 proxy socket ${PKCS11_PROXY_SOCKET}"
fi

pid_file_alive() {
    local pid_file=$1
    [ -s "$pid_file" ] && kill -0 "$(cat "$pid_file")" 2>/dev/null
}

run_as_www_data() {
    local command=$1
    su -s /bin/bash www-data -c "cd '$APP_DIR' && set -a && . '$OPERATIONAL_ENV_FILE' && set +a && export TRUSTPOINT_PHASE='operational' && export DJANGO_SETTINGS_MODULE='trustpoint.settings' && export UV_CACHE_DIR='$UV_CACHE_DIR' && export UV_NO_CACHE='$UV_NO_CACHE' && export HOME='$WWW_DATA_HOME' && $command"
}

wait_for_postgres() {
    local attempt=1
    local max_attempts=30

    if [ -z "${DATABASE_HOST:-}" ] || [ -z "${DATABASE_PORT:-}" ]; then
        log ERROR "DATABASE_HOST and DATABASE_PORT must be set in $OPERATIONAL_ENV_FILE"
        exit 3
    fi

    log INFO "Checking PostgreSQL availability at ${DATABASE_HOST}:${DATABASE_PORT}"
    until pg_isready -h "$DATABASE_HOST" -p "$DATABASE_PORT" >/dev/null 2>&1; do
        if [ "$attempt" -ge "$max_attempts" ]; then
            log ERROR "PostgreSQL did not become available after $max_attempts attempts"
            exit 4
        fi
        attempt=$((attempt + 1))
        sleep 1
    done
}

run_startup_manager() {
    log INFO "Running operational startup manager"
    run_as_www_data "uv run trustpoint/manage.py startup_manager"
}

start_qcluster() {
    if pid_file_alive "$OPERATIONAL_QCLUSTER_PID_FILE"; then
        log INFO "Operational qcluster is already running with PID $(cat "$OPERATIONAL_QCLUSTER_PID_FILE")"
        return
    fi

    log INFO "Starting operational Django-Q2 qcluster"
    su -s /bin/bash www-data -c "cd '$APP_DIR' && \
        set -a && . '$OPERATIONAL_ENV_FILE' && set +a && \
        export TRUSTPOINT_PHASE='operational' && \
        export DJANGO_SETTINGS_MODULE='trustpoint.settings' && \
        export UV_CACHE_DIR='$UV_CACHE_DIR' && \
        export UV_NO_CACHE='$UV_NO_CACHE' && \
        export HOME='$WWW_DATA_HOME' && \
        uv run trustpoint/manage.py qcluster" > "$LOG_DIR/qcluster.log" 2>&1 &
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
    su -s /bin/bash www-data -c "cd '$DJANGO_APP_DIR' && \
        set -a && . '$OPERATIONAL_ENV_FILE' && set +a && \
        export TRUSTPOINT_PHASE='operational' && \
        export DJANGO_SETTINGS_MODULE='trustpoint.settings' && \
        export UV_CACHE_DIR='$UV_CACHE_DIR' && \
        export UV_NO_CACHE='$UV_NO_CACHE' && \
        export HOME='$WWW_DATA_HOME' && \
        '$APP_DIR/.venv/bin/gunicorn' \
        --bind 0.0.0.0:'$OPERATIONAL_PORT' \
        --workers 4 \
        --timeout 300 \
        --user www-data \
        --group www-data \
        trustpoint.wsgi:application" > "$LOG_DIR/gunicorn-operational.log" 2>&1 &
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
run_startup_manager
start_qcluster
start_operational_gunicorn
switch_nginx_proxy
schedule_bootstrap_gunicorn_shutdown

log INFO "Trustpoint runtime switched to operational mode without container restart"
