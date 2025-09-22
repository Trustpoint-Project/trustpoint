#!/bin/bash
# healthcheck.sh – Prüft Setup-Wizard-Seite über HTTPS mit self-signed Cert

set -euo pipefail

URL="https://127.0.0.1/"
MAX_ATTEMPTS=20
SLEEP_SECONDS=3

echo "🔍 Starte Healthcheck gegen $URL (erlaube self-signed Certs)..."

for i in $(seq 1 "$MAX_ATTEMPTS"); do
  http_response=$(curl -k -L -s -o response.txt -w "%{http_code}" "$URL") || true

  if [ "$http_response" = "200" ]; then
    echo "✅ Erfolg bei Versuch $i"
    break
  else
    echo "⏳ Versuch $i fehlgeschlagen mit Code $http_response – erneuter Versuch in ${SLEEP_SECONDS}s..."
    sleep "$SLEEP_SECONDS"
  fi
done

echo ""
echo "📋 HTTP-Antwortcode: $http_response"
echo ""

if [ "$http_response" != "200" ]; then
  echo "❌ Healthcheck fehlgeschlagen. Vollständige Antwort:"
  cat response.txt
  exit 1
else
  echo "✅ Healthcheck erfolgreich. Vollständige Antwort:"
  cat response.txt
fi
