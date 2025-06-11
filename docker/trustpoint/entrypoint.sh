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


# Running migrations on the database
echo "Creating Migration files..."
run_as_www_data "uv run trustpoint/manage.py makemigrations"
echo "Running migrations on the database..."
run_as_www_data "uv run trustpoint/manage.py migrate"
echo "Finnished makemigrations and migrate."

# Collect static files
echo "Collecting static files..."
run_as_www_data "uv run trustpoint/manage.py collectstatic --noinput"
echo "Static files collected."

# Compile messages (translations)
echo "Compiling Messages..."
run_as_www_data "uv run trustpoint/manage.py compilemessages -l de -l en"
echo "Messages compiled."

echo "Starting cron service..."
cron

# Start Apache server
echo "Starting Apache server..."
exec apache2ctl -D FOREGROUND
