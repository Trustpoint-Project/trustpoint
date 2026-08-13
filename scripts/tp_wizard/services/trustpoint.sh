#!/usr/bin/env bash

build_trustpoint() {
  $BUILD_LOCAL || return 0
  log 'Building Trustpoint image...'
  docker build --quiet -f "$TP_DOCKERFILE" -t "$APP_IMAGE" "$ROOT_DIR"
}

start_trustpoint() {
  build_trustpoint
  remove_compose_service trustpoint
  remove_container trustpoint
  start_container trustpoint --add-host host.docker.internal:host-gateway \
    -p "${TP_HTTP_PORT}:80" -p "${TP_HTTPS_PORT}:443" \
    -e TRUSTPOINT_PHASE=auto -e POSTGRES_DB="$DB_NAME" -e DATABASE_USER="$DB_USER" \
    -e DATABASE_PASSWORD="$DB_PASS" -e DATABASE_HOST=postgres -e DATABASE_PORT=5432 \
    -e TP_ADMIN_USERNAME="$TP_ADMIN_USERNAME" -e TP_ADMIN_PASSWORD="$TP_ADMIN_PASSWORD" \
    -e TP_ADMIN_EMAIL="$TP_ADMIN_EMAIL" -e TP_AUTO_SETUP="$TP_AUTO_SETUP" \
    -e TP_INJECT_DEMO_DATA="$TP_INJECT_DEMO_DATA" -e TP_TLS_DNS_NAMES="$TP_TLS_DNS_NAMES" \
    -e TP_ENABLE_PROMETHEUS_METRICS="$ENABLE_METRICS" \
    -e TP_TLS_IPV4_ADDRESSES="$TP_TLS_IPV4_ADDRESSES" -e TP_TLS_IPV6_ADDRESSES="$TP_TLS_IPV6_ADDRESSES" \
    "$APP_IMAGE"
  ok 'Trustpoint started'
}
