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

echo "Unwrapping DEK..."
if run_as_www_data "uv run trustpoint/manage.py unwrap_dek --token-label 'TrustPoint-SoftHSM'"; then
    echo "DEK unwrapping completed successfully"
else
    echo "DEK unwrapping failed or no DEK found, continuing startup..."
fi

# Configure apache
/etc/trustpoint/wizard/transition/configure_apache.sh

# Configure TLS
/etc/trustpoint/wizard/transition/update_tls.sh

echo "Starting cron service..."
cron

version=$(awk -F\" '/^version =/ { print $2 }' pyproject.toml)
echo "Finished with initalisation"
echo "Trustpoint version: $version"

# Start Apache server
echo "Starting Apache server..."
exec apache2ctl -D FOREGROUND
