#!/usr/bin/env bash

summary_container_state() {
  docker inspect -f '{{.State.Status}}' "$1" 2>/dev/null || printf 'absent'
}

summary_service_row() {
  local label="$1" name="$2" url="${3:-}"
  printf '  %-13s %-10s %s\n' "$label" "$(summary_container_state "$name")" "$url"
}

summary() {
  local service
  printf '\nTrustpoint Wizard\n'
  printf '%-17s %-10s %s\n' 'Service' 'State' 'Access'
  printf '%-17s %-10s %s\n' '-----------------' '----------' '------------------------------'

  for service in "${SERVICES[@]}"; do
    case "$service" in
      db) summary_service_row 'PostgreSQL' postgres "tcp://localhost:${DB_PORT}" ;;
      trustpoint) summary_service_row 'Trustpoint' trustpoint "https://localhost:${TP_HTTPS_PORT}" ;;
      mail) summary_service_row 'Mailpit' mailpit "http://localhost:${MAILPIT_UI_PORT}" ;;
      sftp) summary_service_row 'SFTPGo' sftpgo "http://localhost:${SFTPGO_WEB_PORT}/web/admin" ;;
      worker) summary_service_row 'Worker' "$WF2_WORKER_NAME" 'workflows2_worker' ;;
      softhsm) summary_service_row 'SoftHSM' "$SOFTHSM_NAME" 'network-only' ;;
      monitoring)
        summary_service_row 'Prometheus' "$PROMETHEUS_NAME" 'http://localhost:9090'
        summary_service_row 'Grafana' "$GRAFANA_NAME" 'http://localhost:3000'
        ;;
    esac
  done

  if ! $STATUS_ONLY; then
    printf '\nConfiguration\n'
    printf '  %-18s %s\n' 'Initial login:' "${TP_ADMIN_USERNAME} / ${TP_ADMIN_PASSWORD}"
    printf '  %-18s %s\n' 'Setup mode:' "$([[ "$TP_AUTO_SETUP" == true ]] && printf 'automatic' || printf 'interactive')"
    printf '  %-18s %s\n' 'Metrics:' "$([[ "$ENABLE_METRICS" == true ]] && printf 'enabled (/prometheus/metrics)' || printf 'not requested')"
    printf '  %-18s %s\n' 'Env overlay:' "$ENV_OVERLAY"
    if [[ " ${SERVICES[*]} " == *' monitoring '* ]]; then
      printf '  %-18s %s\n' 'Grafana login:' "${GRAFANA_ADMIN_USER} / $(mask "$GRAFANA_ADMIN_PASSWORD")"
    fi
  fi
  printf '\n'
}
