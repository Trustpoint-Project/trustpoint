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

# run_as_www_data "uv run trustpoint/manage.py reset_db --force"
# run_as_www_data "uv run trustpoint/manage.py inittrustpoint"
# run_as_www_data "uv run trustpoint/manage.py tls_cred"
# run_as_www_data "uv run trustpoint/manage.py add_domains_and_devices"

run_as_www_data "uv run trustpoint/manage.py managestartup"

# Check if we're in auto restore mode (waiting for user input)
WIZARD_STATE_DIR="/etc/trustpoint/wizard/state"
echo "Checking wizard state in: $WIZARD_STATE_DIR"
ls -la "$WIZARD_STATE_DIR" || echo "State directory not found or empty"

if [ -f "$WIZARD_STATE_DIR/WIZARD_AUTO_RESTORE_PASSWORD" ]; then
    echo "Auto restore mode detected (WIZARD_AUTO_RESTORE_PASSWORD) - waiting for backup password via web interface"
    echo "Skipping DEK unwrapping, Apache configuration, and TLS update"
else
    echo "Normal operation mode detected - proceeding with DEK unwrapping and configuration"
    echo "Unwrapping DEK..."
    if run_as_www_data "uv run trustpoint/manage.py unwrap_dek --token-label 'Trustpoint-SoftHSM'"; then
        echo "DEK unwrapping completed successfully"
    else
        echo "DEK unwrapping failed or no DEK found, continuing startup..."
    fi

    # Configure apache
    /etc/trustpoint/wizard/transition/configure_apache.sh

    # Configure TLS
    /etc/trustpoint/wizard/transition/update_tls.sh
fi

echo "Starting cron service..."
cron

version=$(awk -F\" '/^version =/ { print $2 }' pyproject.toml)
echo "Finished with initalisation"
echo "Trustpoint version: $version"

# Start Apache server
echo "Starting Apache server..."
exec apache2ctl -D FOREGROUND
