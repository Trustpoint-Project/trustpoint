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

run_as_www_data "uv run trustpoint/manage.py reset_db --force"
run_as_www_data "uv run trustpoint/manage.py inittrustpoint"
run_as_www_data "uv run trustpoint/manage.py tls_cred"
run_as_www_data "uv run trustpoint/manage.py add_domains_and_devices"

run_as_www_data "uv run trustpoint/manage.py managestartup"

echo "Starting cron service..."
cron

# Start Apache server
echo "Starting Apache server..."
exec apache2ctl -D FOREGROUND
