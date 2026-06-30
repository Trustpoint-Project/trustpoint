#!/usr/bin/env bash
set -euo pipefail

CONTAINER=trustpoint
URL="https://localhost/"
DB_HOST=localhost
DB_PORT=5432
DB_NAME=trustpoint_db
DB_USER=admin
DB_PASS=testing321

echo "⏳ Waiting for HTTPS service on ${URL} …"
for i in {1..30}; do
  if curl --fail -k -s "$URL" >/dev/null; then
    echo "✅ HTTPS endpoint is reachable"
    break
  fi
  echo "…still waiting ($i/30)"
  sleep 2
  if [[ $i -eq 30 ]]; then
    echo "❌ HTTPS service never became ready" >&2
    exit 1
  fi
done

echo "🔒 Checking NGINX SSL setup inside container '$CONTAINER' …"
docker exec "$CONTAINER" bash -lc '
  set -euo pipefail

  if nginx -V 2>&1 | grep -q -- "--with-http_ssl_module"; then
    echo "   NGINX compiled with SSL support"
  else
    echo "   NGINX SSL support NOT detected" >&2
    exit 1
  fi

  nginx -t
  echo "   nginx configuration valid (SSL OK)"

  VHOST=/etc/nginx/sites-enabled/trustpoint
  if [[ -f "$VHOST" ]]; then
    echo "   vhost file $VHOST present"
  else
    echo "   vhost file $VHOST missing" >&2
    exit 1
  fi

  for f in \
    /etc/trustpoint/nginx/tls/nginx-tls-server-key.key \
    /etc/trustpoint/nginx/tls/nginx-tls-server-cert.pem
  do
    if [[ -f "$f" ]]; then
      echo "   cert file $f found"
    else
      echo "   cert file $f missing" >&2
      exit 1
    fi
  done

  if [[ -f /etc/trustpoint/nginx/tls/nginx-tls-server-cert-chain.pem ]]; then
    echo "  ✓ optional chain file /etc/trustpoint/nginx/tls/nginx-tls-server-cert-chain.pem found"
  else
    echo "  ℹ optional chain file /etc/trustpoint/nginx/tls/nginx-tls-server-cert-chain.pem not present (OK)"
  fi
'

echo "🗄️  Checking devices_devicemodel for entries …"
export PGPASSWORD="$DB_PASS"
table_exists=$(psql \
  -h "$DB_HOST" \
  -p "$DB_PORT" \
  -U "$DB_USER" \
  -d "$DB_NAME" \
  -Atc "SELECT to_regclass('public.devices_devicemodel') IS NOT NULL;")

if [[ "$table_exists" != "t" ]]; then
  echo "❌ devices_devicemodel table is missing" >&2
  exit 1
fi

has_entries=$(psql \
  -h "$DB_HOST" \
  -p "$DB_PORT" \
  -U "$DB_USER" \
  -d "$DB_NAME" \
  -Atc "SELECT EXISTS (SELECT 1 FROM public.devices_devicemodel);")

if [[ "$has_entries" == "t" ]]; then
  echo "✅ devices_devicemodel contains at least one row"
  exit 0
fi

echo "❌ devices_devicemodel is empty" >&2
exit 1
