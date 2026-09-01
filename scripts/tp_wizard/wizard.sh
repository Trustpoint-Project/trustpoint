#!/usr/bin/env bash
# shellcheck disable=SC2034 # Wizard state is consumed by runtime and service modules.

wizard_select_services() {
  ask_yes_no 'Start PostgreSQL?' y && state_add db
  ask_yes_no 'Start Trustpoint?' y && state_add trustpoint
  ask_yes_no 'Start Mailpit?' n && state_add mail
  ask_yes_no 'Start SFTPGo?' n && state_add sftp
  ask_yes_no 'Start workflows2 worker?' n && state_add worker
  ask_yes_no 'Start Prometheus and Grafana?' n && { ENABLE_METRICS=true; state_add monitoring; }
  return 0
}

wizard_configure_database() {
  state_has db || return 0
  ask_required 'PostgreSQL database name' "$DB_NAME"; DB_NAME="$REPLY"
  ask_required 'PostgreSQL username' "$DB_USER"; DB_USER="$REPLY"
  ask_password 'PostgreSQL password' "$DB_PASS"; DB_PASS="$REPLY"
  ask_port 'PostgreSQL host port' "$DB_PORT"; DB_PORT="$REPLY"
  APP_DB_HOST=postgres
  APP_DB_PORT=5432
}

wizard_configure_trustpoint() {
  state_has trustpoint || return 0

  if ask_yes_no 'Build Trustpoint from the local source?' y; then
    BUILD_LOCAL=true
    APP_IMAGE=trustpoint:local
  else
    BUILD_LOCAL=false
    ask_required 'Trustpoint image' "$APP_IMAGE"; APP_IMAGE="$REPLY"
  fi

  ask_port 'Trustpoint HTTP host port' "$TP_HTTP_PORT"; TP_HTTP_PORT="$REPLY"
  ask_port 'Trustpoint HTTPS host port' "$TP_HTTPS_PORT"; TP_HTTPS_PORT="$REPLY"

  if ! state_has db; then
    ask_required 'Trustpoint database host' "$APP_DB_HOST"; APP_DB_HOST="$REPLY"
    ask_port 'Trustpoint database port' "$APP_DB_PORT"; APP_DB_PORT="$REPLY"
    ask_required 'Trustpoint database name' "$DB_NAME"; DB_NAME="$REPLY"
    ask_required 'Trustpoint database user' "$DB_USER"; DB_USER="$REPLY"
    ask_password 'Trustpoint database password' "$DB_PASS"; DB_PASS="$REPLY"
  fi

  ask 'TLS DNS names (comma-separated)' "$TP_TLS_DNS_NAMES"; TP_TLS_DNS_NAMES="$REPLY"
  ask 'TLS IPv4 addresses (comma-separated, optional)' "$TP_TLS_IPV4_ADDRESSES"
  TP_TLS_IPV4_ADDRESSES="$REPLY"
  ask 'TLS IPv6 addresses (comma-separated, optional)' "$TP_TLS_IPV6_ADDRESSES"
  TP_TLS_IPV6_ADDRESSES="$REPLY"

  if ask_yes_no 'Skip the Trustpoint in-app setup wizard and configure automatically?' n; then
    TP_AUTO_SETUP=true
    ask_required 'Initial Trustpoint admin username' "$TP_ADMIN_USERNAME"; TP_ADMIN_USERNAME="$REPLY"
    ask_password 'Initial Trustpoint admin password' "$TP_ADMIN_PASSWORD"; TP_ADMIN_PASSWORD="$REPLY"
    ask 'Initial Trustpoint admin email' "$TP_ADMIN_EMAIL"; TP_ADMIN_EMAIL="$REPLY"
    if ask_yes_no 'Inject Trustpoint demo data?' y; then
      TP_INJECT_DEMO_DATA=true
    else
      TP_INJECT_DEMO_DATA=false
    fi
  else
    TP_AUTO_SETUP=false
    TP_INJECT_DEMO_DATA=false
  fi
}

wizard_configure_mailpit() {
  state_has mail || return 0
  ask_port 'Mailpit SMTP host port' "$MAILPIT_SMTP_PORT"; MAILPIT_SMTP_PORT="$REPLY"
  ask_port 'Mailpit web UI host port' "$MAILPIT_UI_PORT"; MAILPIT_UI_PORT="$REPLY"
}

wizard_configure_sftpgo() {
  state_has sftp || return 0
  ask_port 'SFTPGo SFTP host port' "$SFTPGO_SFTP_PORT"; SFTPGO_SFTP_PORT="$REPLY"
  ask_port 'SFTPGo web UI host port' "$SFTPGO_WEB_PORT"; SFTPGO_WEB_PORT="$REPLY"
  ask_required 'SFTPGo admin username' "$SFTPGO_ADMIN_USER"; SFTPGO_ADMIN_USER="$REPLY"
  ask_password 'SFTPGo admin password' "$SFTPGO_ADMIN_PASSWORD"; SFTPGO_ADMIN_PASSWORD="$REPLY"
}

wizard_configure_worker() {
  state_has worker || return 0
  ask_required 'Worker ID' "$WF2_WORKER_ID"; WF2_WORKER_ID="$REPLY"
  ask_uint 'Worker lease seconds' "$WF2_WORKER_LEASE"; WF2_WORKER_LEASE="$REPLY"
  ask_uint 'Worker batch size' "$WF2_WORKER_BATCH"; WF2_WORKER_BATCH="$REPLY"
  ask_uint 'Worker sleep seconds' "$WF2_WORKER_SLEEP"; WF2_WORKER_SLEEP="$REPLY"
}

wizard_configure_monitoring() {
  state_has monitoring || return 0
  ask_port 'Prometheus host port' "$PROMETHEUS_PORT"; PROMETHEUS_PORT="$REPLY"
  ask_port 'Grafana host port' "$GRAFANA_PORT"; GRAFANA_PORT="$REPLY"
  ask_required 'Grafana admin username' "$GRAFANA_ADMIN_USER"; GRAFANA_ADMIN_USER="$REPLY"
  ask_password 'Grafana admin password' "$GRAFANA_ADMIN_PASSWORD"; GRAFANA_ADMIN_PASSWORD="$REPLY"
}

wizard_show_plan() {
  printf '\nSelected services: %s\n' "${SERVICES[*]:-(none)}"
  if state_has trustpoint; then
    printf 'Trustpoint setup: %s\n' "$([[ "$TP_AUTO_SETUP" == true ]] && printf automatic || printf 'in-app wizard')"
    printf 'Trustpoint URL: https://localhost:%s\n' "$TP_HTTPS_PORT"
    printf 'Database target: %s:%s/%s (%s)\n' "$APP_DB_HOST" "$APP_DB_PORT" "$DB_NAME" "$DB_USER"
  fi
  printf 'Runtime env: %s\n\n' "$ENV_OVERLAY"
}

interactive_wizard() {
  state_reset
  printf 'Trustpoint setup wizard\n\n'
  wizard_select_services
  ((${#SERVICES[@]} > 0)) || { warn 'No services selected.'; return 0; }

  wizard_configure_database
  wizard_configure_trustpoint
  wizard_configure_mailpit
  wizard_configure_sftpgo
  wizard_configure_worker
  wizard_configure_monitoring
  wizard_show_plan

  ask_yes_no 'Start these services?' y || { warn 'Cancelled.'; return 0; }
  runtime_start
  summary
}
