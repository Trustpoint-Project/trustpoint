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

# Reset the database if the RESET_DB file exists
RESET_DB_FILE="/etc/trustpoint/RESET_DB"

if [ -f "$RESET_DB_FILE" ]; then
  # Reset the database
  echo "Resetting the database..."
  run_as_www_data "uv run trustpoint/manage.py reset_db --no-user --force"
  echo "Database reset."
  rm -f "$RESET_DB_FILE"
else
  echo "Skipping database reset."
fi

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
