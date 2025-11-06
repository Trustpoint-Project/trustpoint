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

run_as_www_data "uv run trustpoint/manage.py startup_manager"

# Configure apache (always needed)
/etc/trustpoint/wizard/transition/configure_apache.sh

# Configure TLS (always needed - will gracefully handle missing files)
/etc/trustpoint/wizard/transition/update_tls.sh

echo "Starting cron service..."
cron

version=$(awk -F\" '/^version =/ { print $2 }' pyproject.toml)
echo "Finished with initalisation"
echo "Trustpoint version: $version"

# Start Apache server
echo "Starting Apache server..."
exec apache2ctl -D FOREGROUND
