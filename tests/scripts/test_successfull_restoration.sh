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

# 1) Wait for HTTPS service on port 443
echo "⏳ Waiting for HTTPS service on https://localhost/ …"
for i in {1..30}; do
  if curl --fail -k -s "$URL" >/dev/null; then
    echo "✅ HTTPS endpoint is reachable"
    break
  fi
  echo "…still waiting ($i/30)"; sleep 2
  if [[ $i -eq 30 ]]; then
    echo "❌ HTTPS service never became ready" >&2
    exit 1
  fi
done

# 2) Inside-container SSL config & cert checks
echo "🔒 Checking NGINX SSL setup inside container '$CONTAINER' …"
docker exec "$CONTAINER" bash -lc '
  set -e
  # 2.1) Check nginx process is running with SSL support
  if nginx -V 2>&1 | grep -q -- "--with-http_ssl_module"; then
    echo "   NGINX compiled with SSL support"
  else
    echo "   NGINX SSL support NOT detected" >&2
    exit 1
  fi

  # 2.2) Test nginx configuration (verifies SSL directives)
  if nginx -t; then
    echo "   nginx configuration valid (SSL OK)"
  else
    echo "   nginx configuration invalid" >&2
    exit 1
  fi

 # 2.3) Check vhost config file
  VHOST=/etc/nginx/sites-enabled/trustpoint
  if [[ -f "$VHOST" ]]; then
    echo "   vhost file $VHOST present"
  else
    echo "   vhost file $VHOST missing" >&2
    exit 1
  fi

   # 2.4) Certificate files (nginx TLS paths)
  for f in \
    /etc/trustpoint/tls/nginx-tls-server-key.key \
    /etc/trustpoint/tls/nginx-tls-server-cert.pem
  do
    if [[ -f "$f" ]]; then
      echo "   cert file $f found"
    else
      echo "   cert file $f missing" >&2
      exit 1
    fi
  done

  # Chain file is optional
  if [[ -f /etc/trustpoint/tls/nginx-tls-server-cert-chain.pem ]]; then
    echo "  ✓ optional chain file /etc/trustpoint/tls/nginx-tls-server-cert-chain.pem found"
  else
    echo "  ℹ optional chain file /etc/trustpoint/tls/nginx-tls-server-cert-chain.pem not present (OK)"
  fi
'

# 3) Database check for devices_devicemodel rows
echo "🗄️  Checking devices_devicemodel for entries …"#!/usr/bin/env bash
set -euo pipefail

# === Configuration ===
CONTAINER=trustpoint
URL="https://localhost/"
DB_HOST=localhost
DB_PORT=5432
DB_NAME=trustpoint_db
DB_USER=admin
DB_PASS=testing321

# 1) Wait for HTTPS service on port 443
echo "⏳ Waiting for HTTPS service on https://localhost/ …"
for i in {1..30}; do
  if curl --fail -k -s "$URL" >/dev/null; then
    echo "✅ HTTPS endpoint is reachable"
    break
  fi
  echo "…still waiting ($i/30)"; sleep 2
  if [[ $i -eq 30 ]]; then
    echo "❌ HTTPS service never became ready" >&2
    exit 1
  fi
done

# 2) Inside-container SSL config & cert checks
echo "🔒 Checking NGINX SSL setup inside container '$CONTAINER' …"
docker exec "$CONTAINER" bash -lc '
  set -e
  # 2.1) Check nginx process is running with SSL support
  if nginx -V 2>&1 | grep -q -- "--with-http_ssl_module"; then
    echo "   NGINX compiled with SSL support"
  else
    echo "   NGINX SSL support NOT detected" >&2
    exit 1
  fi

  # 2.2) Test nginx configuration (verifies SSL directives)
  if nginx -t; then
    echo "   nginx configuration valid (SSL OK)"
  else
    echo "   nginx configuration invalid" >&2
    exit 1
  fi

 # 2.3) Check vhost config file
  VHOST=/etc/nginx/sites-enabled/trustpoint
  if [[ -f "$VHOST" ]]; then
    echo "   vhost file $VHOST present"
  else
    echo "   vhost file $VHOST missing" >&2
    exit 1
  fi

   # 2.4) Certificate files (nginx TLS paths)
  for f in \
    /etc/trustpoint/tls/nginx-tls-server-key.key \
    /etc/trustpoint/tls/nginx-tls-server-cert.pem
  do
    if [[ -f "$f" ]]; then
      echo "   cert file $f found"
    else
      echo "   cert file $f missing" >&2
      exit 1
    fi
  done

  # Chain file is optional
  if [[ -f /etc/trustpoint/tls/nginx-tls-server-cert-chain.pem ]]; then
    echo "  ✓ optional chain file /etc/trustpoint/tls/nginx-tls-server-cert-chain.pem found"
  else
    echo "  ℹ optional chain file /etc/trustpoint/tls/nginx-tls-server-cert-chain.pem not present (OK)"
  fi
'

# 3) Database check for devices_devicemodel rows
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
  exit 1
fi

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
  exit 1
fi
