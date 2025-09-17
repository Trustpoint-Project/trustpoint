#!/bin/bash
set -e  # Exit on error

run_as_www_data() {
  su -s /bin/bash www-data -c "$1"
}

# Wait for the database to be ready
echo "Waiting for PostgreSQL database..."
until pg_isready -h "$DATABASE_HOST" -p "$DATABASE_PORT" &>/dev/null; do
  sleep 1
done
echo "PostgreSQL database is available!"
run_as_www_data "uv run trustpoint/manage.py managestartup"




#  Configure nginx
/etc/trustpoint/wizard/transition/configure_nginx.sh

/etc/trustpoint/wizard/transition/update_tls_nginx.sh
ln -sf /etc/nginx/sites-available/trustpoint /etc/nginx/sites-enabled/trustpoint
echo "Starting cron service..."
cron

version=$(awk -F\" '/^version =/ { print $2 }' pyproject.toml)
echo "Finished with initialisation"
echo "Trustpoint version: $version"

# Start Gunicorn in background
echo "Starting Gunicorn server..."
su -s /bin/bash www-data -c "cd /var/www/html/trustpoint/trustpoint && \
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
