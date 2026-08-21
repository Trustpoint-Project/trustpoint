#!/usr/bin/env bash

env_set() {
  local file="$1" key="$2" value="$3" tmp
  mkdir -p "$(dirname "$file")"; touch "$file"; tmp="$(mktemp)"
  awk -v k="$key" -v v="$value" 'BEGIN{done=0} $0 ~ "^[[:space:]]*" k "=" {if(!done){print k "=" v;done=1};next} {print} END{if(!done) print k "=" v}' "$file" >"$tmp"
  mv "$tmp" "$file"; chmod 600 "$file" 2>/dev/null || true
}

write_runtime_env() {
  env_set "$ENV_OVERLAY" POSTGRES_DB "$DB_NAME"
  env_set "$ENV_OVERLAY" DATABASE_USER "$DB_USER"
  env_set "$ENV_OVERLAY" DATABASE_PASSWORD "$DB_PASS"
  env_set "$ENV_OVERLAY" DATABASE_HOST postgres
  env_set "$ENV_OVERLAY" DATABASE_PORT 5432
  env_set "$ENV_OVERLAY" TP_ADMIN_USERNAME "$TP_ADMIN_USERNAME"
  env_set "$ENV_OVERLAY" TP_ADMIN_PASSWORD "$TP_ADMIN_PASSWORD"
  env_set "$ENV_OVERLAY" TP_ADMIN_EMAIL "$TP_ADMIN_EMAIL"
  env_set "$ENV_OVERLAY" TP_AUTO_SETUP "$TP_AUTO_SETUP"
  env_set "$ENV_OVERLAY" TP_INJECT_DEMO_DATA "$TP_INJECT_DEMO_DATA"
  env_set "$ENV_OVERLAY" TP_ENABLE_PROMETHEUS_METRICS "$ENABLE_METRICS"
  env_set "$ENV_OVERLAY" TP_TLS_DNS_NAMES "$TP_TLS_DNS_NAMES"
  env_set "$ENV_OVERLAY" TP_TLS_IPV4_ADDRESSES "$TP_TLS_IPV4_ADDRESSES"
  env_set "$ENV_OVERLAY" TP_TLS_IPV6_ADDRESSES "$TP_TLS_IPV6_ADDRESSES"
  ok "Updated wizard env overlay: $ENV_OVERLAY"
}
