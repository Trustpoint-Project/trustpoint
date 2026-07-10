#!/bin/bash
set -e  # Exit on error

ROLE="${TRUSTPOINT_SERVICE_ROLE:-web}"
PHASE="${TRUSTPOINT_PHASE:-auto}"
OPERATIONAL_ENV_FILE="${TRUSTPOINT_OPERATIONAL_ENV_FILE:-/var/lib/trustpoint/bootstrap/operational.env}"
OPERATIONAL_READY_FILE="${TRUSTPOINT_OPERATIONAL_READY_FILE:-/var/lib/trustpoint/bootstrap/operational.ready}"
WWW_DATA_HOME="${WWW_DATA_HOME:-/tmp/trustpoint-www-data-home}"

load_operational_env() {
  if [ -f "$OPERATIONAL_ENV_FILE" ]; then
    # shellcheck disable=SC1090
    set -a
    . "$OPERATIONAL_ENV_FILE"
    set +a
  fi
}

if [ "$PHASE" = "auto" ]; then
  if [ -f "$OPERATIONAL_ENV_FILE" ] && [ -f "$OPERATIONAL_READY_FILE" ]; then
    load_operational_env
    PHASE="operational"
  else
    PHASE="bootstrap"
  fi
elif [ "$PHASE" = "operational" ]; then
  load_operational_env
fi

export TRUSTPOINT_PHASE="$PHASE"

case "$PHASE" in
  bootstrap|operational)
    ;;
  *)
    echo "ERROR: Invalid TRUSTPOINT_PHASE='${PHASE}'. Expected 'bootstrap' or 'operational'."
    exit 64
    ;;
esac

if [ -z "${DJANGO_SETTINGS_MODULE:-}" ]; then
  if [ "$PHASE" = "bootstrap" ]; then
    export DJANGO_SETTINGS_MODULE="trustpoint.settings_bootstrap"
  else
    export DJANGO_SETTINGS_MODULE="trustpoint.settings"
  fi
fi

# If already running as www-data, don't su (prevents password prompt)
run_as_www_data() {
  if [ "$(id -u)" = "0" ]; then
    su -s /bin/bash www-data -c "export TRUSTPOINT_PHASE='${PHASE}'; export DJANGO_SETTINGS_MODULE='${DJANGO_SETTINGS_MODULE}'; $1"
  else
    bash -lc "export TRUSTPOINT_PHASE='${PHASE}'; export DJANGO_SETTINGS_MODULE='${DJANGO_SETTINGS_MODULE}'; $1"
  fi
}

echo "=== Trustpoint role: ${ROLE} ==="
echo "=== Trustpoint phase: ${PHASE} ==="
echo "=== Django settings: ${DJANGO_SETTINGS_MODULE} ==="

mkdir -p /var/log/trustpoint
BOOTSTRAP_STATE_DIR="$(dirname "$OPERATIONAL_ENV_FILE")"
BOOTSTRAP_READY_DIR="$(dirname "$OPERATIONAL_READY_FILE")"
BOOTSTRAP_DB_PATH="${TRUSTPOINT_BOOTSTRAP_DB_PATH:-/var/lib/trustpoint/bootstrap/bootstrap.sqlite3}"
BOOTSTRAP_DB_DIR="$(dirname "$BOOTSTRAP_DB_PATH")"
BOOTSTRAP_RUNTIME_ROOT="$(dirname "$BOOTSTRAP_DB_DIR")"

bootstrap_sqlite_write_probe() {
  su -s /bin/bash www-data -c "python -c \"import sqlite3; p='${BOOTSTRAP_DB_PATH}'; con=sqlite3.connect(p); con.execute('CREATE TABLE IF NOT EXISTS trustpoint_bootstrap_write_probe (id integer primary key)'); con.execute('DROP TABLE trustpoint_bootstrap_write_probe'); con.commit(); con.close()\""
}

repair_bootstrap_sqlite_file() {
  [ -e "$BOOTSTRAP_DB_PATH" ] || return 0

  local repaired_path="${BOOTSTRAP_DB_PATH}.repair"
  local stale_path="${BOOTSTRAP_DB_PATH}.readonly.$(date +%s)"

  cp "$BOOTSTRAP_DB_PATH" "$repaired_path"
  chown www-data:www-data "$repaired_path"
  chmod 660 "$repaired_path"
  mv "$BOOTSTRAP_DB_PATH" "$stale_path"
  mv "$repaired_path" "$BOOTSTRAP_DB_PATH"
}

prepare_bootstrap_sqlite_storage() {
  mkdir -p "$BOOTSTRAP_STATE_DIR" "$BOOTSTRAP_READY_DIR" "$BOOTSTRAP_DB_DIR"

  if [ "$(id -u)" != "0" ]; then
    return 0
  fi

  chown www-data:www-data /var/log/trustpoint
  chown www-data:www-data "$BOOTSTRAP_RUNTIME_ROOT" 2>/dev/null || true
  chown -R www-data:www-data "$BOOTSTRAP_STATE_DIR" "$BOOTSTRAP_READY_DIR" "$BOOTSTRAP_DB_DIR"
  chmod 750 "$BOOTSTRAP_STATE_DIR" "$BOOTSTRAP_READY_DIR" "$BOOTSTRAP_DB_DIR"

  if [ -e "$BOOTSTRAP_DB_PATH" ]; then
    chown www-data:www-data "$BOOTSTRAP_DB_PATH"
    chmod 660 "$BOOTSTRAP_DB_PATH"
  fi

  find "$BOOTSTRAP_DB_DIR" -maxdepth 1 \( -name '*.sqlite3-journal' -o -name '*.sqlite3-wal' -o -name '*.sqlite3-shm' \) \
    -exec chown www-data:www-data {} \; \
    -exec chmod 660 {} \; 2>/dev/null || true

  su -s /bin/bash www-data -c "test -w '$BOOTSTRAP_DB_DIR' && touch '$BOOTSTRAP_DB_DIR/.trustpoint-write-test' && rm -f '$BOOTSTRAP_DB_DIR/.trustpoint-write-test'"

  if [ "$PHASE" != "bootstrap" ]; then
    return 0
  fi

  if ! bootstrap_sqlite_write_probe; then
    echo "WARNING: Bootstrap SQLite write probe failed; repairing database file permissions."
    repair_bootstrap_sqlite_file
    find "$BOOTSTRAP_DB_DIR" -maxdepth 1 \( -name '*.sqlite3-journal' -o -name '*.sqlite3-wal' -o -name '*.sqlite3-shm' \) \
      -exec rm -f {} \; 2>/dev/null || true
    bootstrap_sqlite_write_probe
  fi
}

mkdir -p "$BOOTSTRAP_STATE_DIR" "$BOOTSTRAP_READY_DIR"
mkdir -p "$BOOTSTRAP_DB_DIR"
if [ "$(id -u)" = "0" ]; then
  prepare_bootstrap_sqlite_storage
fi

wait_for_postgres() {
  echo "Waiting for PostgreSQL database..."
  until pg_isready -h "$DATABASE_HOST" -p "$DATABASE_PORT" &>/dev/null; do
    sleep 1
  done
  echo "PostgreSQL database is available!"
}

configure_web_edge() {
  # Configure TLS (always needed - will gracefully handle missing files)
  /etc/trustpoint/wizard/update_tls.sh

  # Configure nginx
  /etc/trustpoint/wizard/configure_nginx.sh
}

start_gunicorn() {
  echo "Starting Gunicorn server..."
  mkdir -p "$WWW_DATA_HOME"
  chown www-data:www-data "$WWW_DATA_HOME"
  su -s /bin/bash www-data -c "cd /var/www/html/trustpoint/trustpoint && \
      export TRUSTPOINT_PHASE='${PHASE}' && \
      export DJANGO_SETTINGS_MODULE='${DJANGO_SETTINGS_MODULE}' && \
      export HOME='${WWW_DATA_HOME}' && \
      /var/www/html/trustpoint/.venv/bin/gunicorn \
      --bind 0.0.0.0:8000 \
      --workers 4 \
      --timeout 300 \
      --user www-data \
      --group www-data \
      trustpoint.wsgi:application" > /var/log/trustpoint/gunicorn.log 2>&1 &
  GUNICORN_PID=$!
  echo "Gunicorn started with PID $GUNICORN_PID"

  sleep 2

  if ! kill -0 $GUNICORN_PID 2>/dev/null; then
    echo "ERROR: Gunicorn failed to start. Check /var/log/trustpoint/gunicorn.log"
    cat /var/log/trustpoint/gunicorn.log
    exit 1
  fi
}

start_nginx_foreground() {
  echo "Starting Nginx server..."
  exec nginx -g 'daemon off;'
}

# ---------------- WORKER ROLE ----------------
if [ "$ROLE" = "worker" ]; then
  if [ "$PHASE" = "bootstrap" ]; then
    echo "=== Bootstrap phase: worker role is waiting for explicit operational handoff ==="
    until [ -f "$OPERATIONAL_ENV_FILE" ] && [ -f "$OPERATIONAL_READY_FILE" ]; do
      sleep 5
    done
    load_operational_env
    PHASE="operational"
    export TRUSTPOINT_PHASE="$PHASE"
    export DJANGO_SETTINGS_MODULE="trustpoint.settings"
    echo "=== Worker role received operational handoff ==="
  fi

  wait_for_postgres
  echo "=== Starting Trustpoint WORKER role (no web stack) ==="

  exec su -s /bin/bash www-data -c "export TRUSTPOINT_PHASE='${PHASE}' && \
    export DJANGO_SETTINGS_MODULE='${DJANGO_SETTINGS_MODULE}' && \
    uv run trustpoint/manage.py workflows2_worker \
    --id '${WORKFLOWS2_WORKER_ID:-$(hostname)}' \
    --lease '${WORKFLOWS2_WORKER_LEASE:-30}' \
    --batch '${WORKFLOWS2_WORKER_BATCH:-10}' \
    --sleep '${WORKFLOWS2_WORKER_SLEEP:-1}'"
fi

if [ "$PHASE" = "bootstrap" ]; then
  echo "=== Starting Trustpoint BOOTSTRAP web role ==="
  run_as_www_data "uv run trustpoint/manage.py bootstrap_manager"
  
  # Check if auto-setup was requested and trigger operational switch immediately
  AUTO_SETUP_MARKER="/var/lib/trustpoint/bootstrap/auto-setup.marker"
  if [ -f "$AUTO_SETUP_MARKER" ]; then
    echo "Auto-setup marker detected - triggering immediate switch to operational mode"
    if [ -f "/etc/trustpoint/wizard/switch_to_operational.sh" ]; then
      sudo /etc/trustpoint/wizard/switch_to_operational.sh "$OPERATIONAL_ENV_FILE"
      echo "Operational mode activated - container will now serve operational runtime"
      exit 0
    else
      echo "ERROR: switch_to_operational.sh not found, cannot auto-switch"
      exit 1
    fi
  fi
  
  configure_web_edge
  start_gunicorn
  trap "kill $GUNICORN_PID 2>/dev/null; exit 0" SIGTERM SIGINT
  start_nginx_foreground
fi

# ---------------- OPERATIONAL WEB ROLE ----------------
wait_for_postgres
run_as_www_data "uv run trustpoint/manage.py startup_manager"
configure_web_edge

echo "Starting cron service..."
cron

version=$(awk -F\" '/^version =/ { print $2 }' pyproject.toml)
echo "Finished with initialisation"
echo "Trustpoint version: $version"

echo "Starting Django-Q2 qcluster worker..."
su -s /bin/bash www-data -c "cd /var/www/html/trustpoint && \
    export TRUSTPOINT_PHASE='${PHASE}' && \
    export DJANGO_SETTINGS_MODULE='${DJANGO_SETTINGS_MODULE}' && \
    uv run trustpoint/manage.py qcluster" > /var/log/trustpoint/qcluster.log 2>&1 &
QCLUSTER_PID=$!
echo "Django-Q2 qcluster started with PID $QCLUSTER_PID"

sleep 3

# Check if qcluster is still running
if ! kill -0 $QCLUSTER_PID 2>/dev/null; then
  echo "ERROR: Django-Q2 qcluster failed to start. Check /var/log/trustpoint/qcluster.log"
  cat /var/log/trustpoint/qcluster.log
  exit 1
fi

start_gunicorn

trap "kill $QCLUSTER_PID $GUNICORN_PID 2>/dev/null; exit 0" SIGTERM SIGINT

start_nginx_foreground
