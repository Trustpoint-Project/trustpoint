#!/usr/bin/env bash
set -euo pipefail

# === Configuration ===
URL="https://localhost/"
DB_HOST="localhost"
DB_PORT="5432"
DB_NAME="trustpoint_db"
DB_USER="admin"
DB_PASS="testing321"

# === 1) Check URL reachability ===
echo "Checking reachability of $URL …"
if curl --fail -k -s "$URL" >/dev/null; then
  echo "✅ URL is reachable"
else
  echo "❌ URL is NOT reachable" >&2
  exit 1
fi

# === 2) Check devices_devicemodel table for entries ===
export PGPASSWORD="$DB_PASS"

echo "Checking for entries in devices_devicemodel …"
has_entries=$(psql \
  -h "$DB_HOST" -p "$DB_PORT" \
  -U "$DB_USER" -d "$DB_NAME" \
  -Atc "SELECT EXISTS (SELECT 1 FROM devices_devicemodel);")

if [[ "$has_entries" == "t" ]]; then
  echo "✅ devices_devicemodel contains at least one row"
  exit 0
else
  echo "❌ devices_devicemodel is empty" >&2
  exit 1
fi
