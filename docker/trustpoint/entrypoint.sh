#!/bin/bash
set -e  # Exit on error

ROLE="${TRUSTPOINT_SERVICE_ROLE:-web}"

# If already running as www-data, don't su (prevents password prompt)
run_as_www_data() {
  if [ "$(id -u)" = "0" ]; then
    su -s /bin/bash www-data -c "$1"
  else
    bash -lc "$1"
  fi
}

echo "=== Trustpoint role: ${ROLE} ==="

# Wait for the database to be ready
echo "Waiting for PostgreSQL database..."
until pg_isready -h "$DATABASE_HOST" -p "$DATABASE_PORT" &>/dev/null; do
  sleep 1
done
echo "PostgreSQL database is available!"

# ---------------- WORKER ROLE ----------------
if [ "$ROLE" = "worker" ]; then
  echo "=== Starting Trustpoint WORKER role (no web stack) ==="

  exec su -s /bin/bash www-data -c "uv run trustpoint/manage.py workflows2_worker \
    --id '${WORKFLOWS2_WORKER_ID:-$(hostname)}' \
    --lease '${WORKFLOWS2_WORKER_LEASE:-30}' \
    --batch '${WORKFLOWS2_WORKER_BATCH:-10}' \
    --sleep '${WORKFLOWS2_WORKER_SLEEP:-1}'"
fi

# ---------------- WEB ROLE (existing behavior) ----------------
run_as_www_data "uv run trustpoint/manage.py startup_manager"

# Configure TLS (always needed - will gracefully handle missing files)
/etc/trustpoint/wizard/transition/update_tls.sh

# Configure nginx
/etc/trustpoint/wizard/transition/configure_nginx.sh

echo "Starting cron service..."
cron

version=$(awk -F\" '/^version =/ { print $2 }' pyproject.toml)
echo "Finished with initialisation"
echo "Trustpoint version: $version"

# Start Gunicorn in background
echo "Starting Gunicorn server..."
run_as_www_data "cd /var/www/html/trustpoint/trustpoint && \
  /var/www/html/trustpoint/.venv/bin/gunicorn \
  --bind 0.0.0.0:8000 \
  --workers 4 \
  --timeout 300 \
  --user www-data \
  --group www-data \
  trustpoint.wsgi:application" &

# Wait for Gunicorn to start
sleep 2

# Start Nginx
echo "Starting Nginx server..."
exec nginx -g 'daemon off;'
