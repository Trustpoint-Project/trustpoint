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
  env_set "$ENV_OVERLAY" DATABASE_HOST "$APP_DB_HOST"
  env_set "$ENV_OVERLAY" DATABASE_PORT "$APP_DB_PORT"
  env_set "$ENV_OVERLAY" TP_HTTP_PORT "$TP_HTTP_PORT"
  env_set "$ENV_OVERLAY" TP_HTTPS_PORT "$TP_HTTPS_PORT"
  env_set "$ENV_OVERLAY" TP_ADMIN_USERNAME "$TP_ADMIN_USERNAME"
  env_set "$ENV_OVERLAY" TP_ADMIN_PASSWORD "$TP_ADMIN_PASSWORD"
  env_set "$ENV_OVERLAY" TP_ADMIN_EMAIL "$TP_ADMIN_EMAIL"
  env_set "$ENV_OVERLAY" TP_AUTO_SETUP "$TP_AUTO_SETUP"
  env_set "$ENV_OVERLAY" TP_INJECT_DEMO_DATA "$TP_INJECT_DEMO_DATA"
  env_set "$ENV_OVERLAY" TP_ENABLE_PROMETHEUS_METRICS "$ENABLE_METRICS"
  env_set "$ENV_OVERLAY" TP_TLS_DNS_NAMES "$TP_TLS_DNS_NAMES"
  env_set "$ENV_OVERLAY" TP_TLS_IPV4_ADDRESSES "$TP_TLS_IPV4_ADDRESSES"
  env_set "$ENV_OVERLAY" TP_TLS_IPV6_ADDRESSES "$TP_TLS_IPV6_ADDRESSES"
  env_set "$ENV_OVERLAY" MAILPIT_SMTP_PORT "$MAILPIT_SMTP_PORT"
  env_set "$ENV_OVERLAY" MAILPIT_UI_PORT "$MAILPIT_UI_PORT"
  env_set "$ENV_OVERLAY" SFTPGO_SFTP_PORT "$SFTPGO_SFTP_PORT"
  env_set "$ENV_OVERLAY" SFTPGO_WEB_PORT "$SFTPGO_WEB_PORT"
  env_set "$ENV_OVERLAY" SFTPGO_ADMIN_USER "$SFTPGO_ADMIN_USER"
  env_set "$ENV_OVERLAY" SFTPGO_ADMIN_PASSWORD "$SFTPGO_ADMIN_PASSWORD"
  env_set "$ENV_OVERLAY" PROMETHEUS_PORT "$PROMETHEUS_PORT"
  env_set "$ENV_OVERLAY" GRAFANA_PORT "$GRAFANA_PORT"
  env_set "$ENV_OVERLAY" GRAFANA_ADMIN_USER "$GRAFANA_ADMIN_USER"
  env_set "$ENV_OVERLAY" GRAFANA_ADMIN_PASSWORD "$GRAFANA_ADMIN_PASSWORD"
  ok "Updated wizard env overlay: $ENV_OVERLAY"
}
