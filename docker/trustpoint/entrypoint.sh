#!/bin/bash
set -e  # Exit on error

if [ "${1:-}" != "--validated" ] || [ "${_TRUSTPOINT_VALIDATED:-}" != "1" ]; then
  exec /usr/local/bin/python3 -I /etc/trustpoint/runtime_config.py entrypoint
fi
shift

ROLE="${TRUSTPOINT_SERVICE_ROLE:-web}"
PHASE="${TRUSTPOINT_PHASE:-auto}"
OPERATIONAL_ENV_FILE="${TRUSTPOINT_OPERATIONAL_ENV_FILE:-/var/lib/trustpoint/bootstrap/operational.env}"
OPERATIONAL_READY_FILE="${TRUSTPOINT_OPERATIONAL_READY_FILE:-/var/lib/trustpoint/bootstrap/operational.ready}"
WWW_DATA_HOME="${WWW_DATA_HOME:-/tmp/trustpoint-www-data-home}"

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

echo "=== Trustpoint role: ${ROLE} ==="
echo "=== Trustpoint phase: ${PHASE} ==="
echo "=== Django settings: ${DJANGO_SETTINGS_MODULE} ==="

mkdir -p /var/log/trustpoint
chown root:root /var/log/trustpoint
chmod 755 /var/log/trustpoint

wait_for_postgres() {
  echo "Waiting for PostgreSQL database..."
  until /usr/local/bin/python3 -I /etc/trustpoint/runtime_config.py app db-ready &>/dev/null; do
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
  /usr/local/bin/python3 -I /etc/trustpoint/runtime_config.py app web > /var/log/trustpoint/gunicorn.log 2>&1 &
  GUNICORN_PID=$!
  echo "Gunicorn started with PID $GUNICORN_PID"

  sleep 2

  if ! kill -0 $GUNICORN_PID 2>/dev/null; then
    echo "ERROR: Gunicorn failed to start. Check /var/log/trustpoint/gunicorn.log"
    cat /var/log/trustpoint/gunicorn.log
    exit 1
  fi
}

service_alive() {
  local field state
  kill -0 "$1" 2>/dev/null || return 1
  if [ -r "/proc/$1/status" ]; then
    while read -r field state _; do
      if [ "$field" = "State:" ]; then
        [ "$state" != "Z" ]
        return
      fi
    done < "/proc/$1/status"
  fi
}

start_nginx_foreground() {
  local handoff_started=""
  echo "Starting Nginx server..."
  nginx -g 'daemon off;' &
  NGINX_PID=$!
  while true; do
    local required_pids=("$NGINX_PID")
    if [ -f /run/trustpoint-operational.ready ]; then
      if [ -z "$handoff_started" ]; then
        handoff_started=$SECONDS
      fi
      if [ -n "${GUNICORN_PID:-}" ] && (( SECONDS - handoff_started >= 10 )); then
        kill -TERM "$GUNICORN_PID" 2>/dev/null || true
        GUNICORN_PID=""
      fi
      required_pids+=("$(cat /run/trustpoint-operational-gunicorn.pid)"
                     "$(cat /run/trustpoint-operational-qcluster.pid)")
    else
      required_pids+=("$GUNICORN_PID")
      if [ -n "${QCLUSTER_PID:-}" ]; then
        required_pids+=("$QCLUSTER_PID")
      fi
    fi
    for pid in "${required_pids[@]}"; do
      if ! service_alive "$pid"; then
        echo "ERROR: Required service $pid exited; stopping the container."
        exit 1
      fi
    done
    sleep 1
  done
}

stop_web_services() {
  local pid_file
  local pids=("${NGINX_PID:-}" "${GUNICORN_PID:-}" "${QCLUSTER_PID:-}")
  for pid_file in /run/trustpoint-operational-{gunicorn,qcluster}.pid; do
    if [ -s "$pid_file" ]; then
      pids+=("$(cat "$pid_file")")
    fi
  done
  # Include children started just before a shutdown signal, before $! was saved.
  for pid in $(jobs -pr); do
    pids+=("$pid")
  done
  for pid in "${pids[@]}"; do
    if [ -n "$pid" ]; then
      kill -TERM "$pid" 2>/dev/null || true
    fi
  done
  # Handoff services are not shell jobs; leave time within Docker's 10-second stop window.
  local deadline=$((SECONDS + 8))
  for pid in "${pids[@]}"; do
    [ -n "$pid" ] || continue
    while service_alive "$pid"; do
      if (( SECONDS >= deadline )); then
        echo "WARNING: Service $pid exceeded the shutdown deadline; killing it."
        kill -KILL "$pid" 2>/dev/null || true
        break
      fi
      sleep 0.1
    done
  done
  wait || true
}

# ---------------- WORKER ROLE ----------------
if [ "$ROLE" = "worker" ]; then
  if [ "$PHASE" = "bootstrap" ]; then
    echo "=== Bootstrap phase: worker role is waiting for explicit operational handoff ==="
    until [ -f "$OPERATIONAL_ENV_FILE" ] && [ -f "$OPERATIONAL_READY_FILE" ]; do
      sleep 5
    done
    exec /usr/local/bin/python3 -I /etc/trustpoint/runtime_config.py resume-worker
  fi

  wait_for_postgres
  echo "=== Starting Trustpoint WORKER role (no web stack) ==="

  /usr/local/bin/python3 -I /etc/trustpoint/runtime_config.py app sync-security
  exec /usr/local/bin/python3 -I /etc/trustpoint/runtime_config.py app worker
fi

rm -f /run/trustpoint-operational.ready /run/trustpoint-operational-{gunicorn,qcluster}.pid
trap stop_web_services EXIT
trap 'exit 0' SIGTERM SIGINT

if [ "$PHASE" = "bootstrap" ]; then
  echo "=== Starting Trustpoint BOOTSTRAP web role ==="
  /usr/local/bin/python3 -I /etc/trustpoint/runtime_config.py app bootstrap
  
  # Check if auto-setup was requested and trigger operational switch immediately
  AUTO_SETUP_MARKER="/var/lib/trustpoint/bootstrap/auto-setup.marker"
  if [ -f "$AUTO_SETUP_MARKER" ]; then
    echo "Auto-setup marker detected - triggering immediate switch to operational mode"
    if [ -f "/etc/trustpoint/wizard/switch_to_operational.sh" ]; then
      /etc/trustpoint/wizard/switch_to_operational.sh --final
      echo "Operational mode activated - starting the web edge without restarting the container"
      # The switch installed TLS and the operational upstream before nginx ran.
      # Enable that configured site without copying the bootstrap upstream back.
      ln -sf /etc/nginx/sites-available/trustpoint /etc/nginx/sites-enabled/trustpoint
      nginx -t
      start_nginx_foreground
    else
      echo "ERROR: switch_to_operational.sh not found, cannot auto-switch"
      exit 1
    fi
  fi
  
  configure_web_edge
  start_gunicorn
  start_nginx_foreground
fi

# ---------------- OPERATIONAL WEB ROLE ----------------
wait_for_postgres
/usr/local/bin/python3 -I /etc/trustpoint/runtime_config.py app startup
configure_web_edge

version=$(awk -F\" '/^version =/ { print $2 }' pyproject.toml)
echo "Finished with initialisation"
echo "Trustpoint version: $version"

echo "Starting Django-Q2 qcluster worker..."
/usr/local/bin/python3 -I /etc/trustpoint/runtime_config.py app qcluster > /var/log/trustpoint/qcluster.log 2>&1 &
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

start_nginx_foreground
