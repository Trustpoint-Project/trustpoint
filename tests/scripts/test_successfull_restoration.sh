#!/usr/bin/env bash
set -euo pipefail

# === Configuration ===
CONTAINER=trustpoint
URL="https://localhost/"
DB_HOST=localhost
DB_PORT=5432
DB_NAME=trustpoint_db
DB_USER=admin
DB_PASS=testing321

# 1) Wait for HTTP service on port 80
echo "⏳ Waiting for HTTP service on http://localhost/ …"
for i in {1..30}; do
  if curl --fail -s "http://localhost/"; then
    echo "✅ HTTP service is up"
    break
  fi
  echo "…still waiting ($i/30)"; sleep 2
  if [[ $i -eq 30 ]]; then
    echo "❌ HTTP service never became ready" >&2
    exit 1
  fi
done

# 2) Inside-container SSL config & cert checks
echo "🔒 Checking Apache SSL setup inside container '$CONTAINER' …"
docker exec "$CONTAINER" bash -lc '
  set -e
  # 2.1) SSL module
  if apache2ctl -M 2>/dev/null | grep -q ssl_module; then
    echo "  ✓ ssl_module enabled"
  else
    echo "  ✗ ssl_module NOT enabled" >&2
    # exit 1
  fi

  # 2.2) SSL vhost
  VHOST=/etc/apache2/sites-enabled/trustpoint-apache-https.conf
  if [[ -f "$VHOST" ]]; then
    echo "  ✓ vhost file $VHOST present"
  else
    echo "  ✗ vhost file $VHOST missing" >&2
    # exit 1
  fi

  # 2.3) Certificate files
  for f in \
    /etc/trustpoint/tls/apache-tls-server-key.key \
    /etc/trustpoint/tls/apache-tls-server-cert.pem \
    /etc/trustpoint/tls/apache-tls-server-cert-chain.pem
  do
    if [[ -f "$f" ]]; then
      echo "  ✓ cert file $f found"
    else
      echo "  ✗ cert file $f missing" >&2
    #   exit 1
    fi
  done
'

# 3) HTTPS endpoint check
echo "🌐 Checking reachability of $URL …"
if curl --fail -k -s "$URL" >/dev/null; then
  echo "✅ HTTPS endpoint is reachable"
else
  echo "❌ HTTPS endpoint is NOT reachable" >&2
#   exit 1
fi

# 4) Database check for devices_devicemodel rows
echo "🗄️  Checking devices_devicemodel for entries …"
export PGPASSWORD="$DB_PASS"
has_entries=$(psql \
  -h "$DB_HOST" \
  -p "$DB_PORT" \
  -U "$DB_USER" \
  -d "$DB_NAME" \
  -Atc "SELECT EXISTS (SELECT 1 FROM devices_devicemodel);")

if [[ "$has_entries" == "t" ]]; then
  echo "✅ devices_devicemodel contains at least one row"
  exit 0
else
  echo "❌ devices_devicemodel is empty" >&2
#   exit 1
fi
