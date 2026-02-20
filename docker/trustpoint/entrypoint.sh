#!/bin/bash
set -e  # Exit on error

run_as_www_data() {
  su -s /bin/bash www-data -c "$1"
}

mkdir -p /var/log/trustpoint
chown www-data:www-data /var/log/trustpoint

# Wait for the database to be ready
echo "Waiting for PostgreSQL database..."
until pg_isready -h "$DATABASE_HOST" -p "$DATABASE_PORT" &>/dev/null; do
  sleep 1
done
echo "PostgreSQL database is available!"

run_as_www_data "uv run trustpoint/manage.py startup_manager"

# Configure TLS (always needed - will gracefully handle missing files)
/etc/trustpoint/wizard/transition/update_tls.sh

#  Configure nginx
/etc/trustpoint/wizard/transition/configure_nginx.sh


echo "Starting cron service..."
cron

version=$(awk -F\" '/^version =/ { print $2 }' pyproject.toml)
echo "Finished with initialisation"
echo "Trustpoint version: $version"

echo "Starting Django-Q2 qcluster worker..."
su -s /bin/bash www-data -c "cd /var/www/html/trustpoint && \
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

# Start Gunicorn in background
echo "Starting Gunicorn server..."
su -s /bin/bash www-data -c "cd /var/www/html/trustpoint/trustpoint && \
    /var/www/html/trustpoint/.venv/bin/gunicorn \
    --bind 0.0.0.0:8000 \
    --workers 4 \
    --timeout 300 \
    --user www-data \
    --group www-data \
    trustpoint.wsgi:application" > /var/log/trustpoint/gunicorn.log 2>&1 &
GUNICORN_PID=$!
echo "Gunicorn started with PID $GUNICORN_PID"

# Wait for Gunicorn to start
sleep 2

if ! kill -0 $GUNICORN_PID 2>/dev/null; then
  echo "ERROR: Gunicorn failed to start. Check /var/log/trustpoint/gunicorn.log"
  cat /var/log/trustpoint/gunicorn.log
  exit 1
fi

trap "kill $QCLUSTER_PID $GUNICORN_PID 2>/dev/null; exit 0" SIGTERM SIGINT

echo "Starting Nginx server..."
exec nginx -g 'daemon off;'
