#!/usr/bin/env bash

summary_container_state() {
  docker inspect -f '{{.State.Status}}' "$1" 2>/dev/null || printf 'absent'
}

summary_service_row() {
  local label="$1" name="$2" url="${3:-}"
  printf '  %-13s %-10s %s\n' "$label" "$(summary_container_state "$name")" "$url"
}

summary_trustpoint_log_value() {
  local key="$1"
  container_exists trustpoint || return 0
  docker logs trustpoint 2>&1 \
    | sed -nE "s/.*Trustpoint bootstrap ${key}:[[:space:]]*([^[:space:]]+).*/\1/p" \
    | tail -n1
}

summary_tls_fingerprint() {
  container_exists trustpoint || return 0
  docker logs trustpoint 2>&1 \
    | sed -nE 's/.*TLS SHA256 fingerprint:[[:space:]]*(([0-9A-Fa-f]{2}:){31}[0-9A-Fa-f]{2}).*/\1/p' \
    | tail -n1
}

summary_trustpoint_auto_setup() {
  local value="$TP_AUTO_SETUP"
  container_exists trustpoint && value="$(container_env trustpoint TP_AUTO_SETUP)"
  [[ "${value,,}" =~ ^(1|true|yes|on)$ ]]
}

summary_trustpoint_operational() {
  container_exists trustpoint || return 1
  docker logs trustpoint 2>&1 | grep -Eq 'Trustpoint phase: operational|Starting Trustpoint OPERATIONAL'
}

summary_wait_trustpoint_details() {
  $NOWAIT && return 0
  local username password fingerprint
  for ((i=0; i<90; i++)); do
    username="$(summary_trustpoint_log_value username)"
    password="$(summary_trustpoint_log_value password)"
    fingerprint="$(summary_tls_fingerprint)"
    if [[ -n "$fingerprint" ]] && { summary_trustpoint_auto_setup || summary_trustpoint_operational || [[ -n "$username" && -n "$password" ]]; }; then
      return 0
    fi
    container_running trustpoint || return 0
    sleep 1
  done
  warn 'Trustpoint login or TLS fingerprint is not available yet; check status shortly.'
}

summary_trustpoint_configuration() {
  local username password fingerprint usb_hsm_access soft_hsm_access
  fingerprint="$(summary_tls_fingerprint)"
  usb_hsm_access="$ENABLE_USB_PASSTHROUGH"
  soft_hsm_access=0
  if container_exists trustpoint; then
    usb_hsm_access="$(container_env trustpoint TP_USB_HSM_PASSTHROUGH)"
    soft_hsm_access="$(container_env trustpoint TRUSTPOINT_LOCAL_HSM_ENABLED)"
  fi

  if summary_trustpoint_auto_setup; then
    username="$(container_env trustpoint TP_ADMIN_USERNAME)"
    password="$(container_env trustpoint TP_ADMIN_PASSWORD)"
    printf '  %-18s %s\n' 'Trustpoint login:' "${username:-$TP_ADMIN_USERNAME} / ${password:-$TP_ADMIN_PASSWORD}"
    printf '  %-18s %s\n' 'Setup mode:' 'automatic (--skip-wizard)'
  else
    username="$(summary_trustpoint_log_value username)"
    password="$(summary_trustpoint_log_value password)"
    if [[ -n "$username" && -n "$password" ]]; then
      printf '  %-18s %s\n' 'Setup login:' "$username / $password"
    else
      printf '  %-18s %s\n' 'Setup login:' 'not found in logs yet'
    fi
    printf '  %-18s %s\n' 'Setup mode:' 'in-app setup wizard'
  fi
  printf '  %-18s %s\n' 'SoftHSM handoff:' "$([[ "$soft_hsm_access" == 1 ]] && printf available || printf disabled)"
  printf '  %-18s %s\n' 'USB HSM access:' "$([[ "${usb_hsm_access,,}" == true ]] && printf enabled || printf disabled)"
  printf '  %-18s %s\n' 'TLS SHA-256:' "${fingerprint:-not found in logs yet}"
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
      softhsm) summary_service_row 'SoftHSM' "$SOFTHSM_NAME" 'local PKCS#11' ;;
      monitoring)
        summary_service_row 'Prometheus' "$PROMETHEUS_NAME" "http://localhost:${PROMETHEUS_PORT}"
        summary_service_row 'Grafana' "$GRAFANA_NAME" "http://localhost:${GRAFANA_PORT}"
        ;;
    esac
  done

  printf '\nConfiguration\n'
  state_has trustpoint && summary_trustpoint_configuration
  if state_has softhsm; then
    local hsm_serial hsm_user_pin
    hsm_serial="$(local_hsm_value TRUSTPOINT_LOCAL_HSM_TOKEN_SERIAL)"
    hsm_user_pin="$(local_hsm_user_pin)"
    printf '  %-18s %s\n' 'HSM token:' "${LOCAL_HSM_TOKEN_LABEL}${hsm_serial:+ ($hsm_serial)}"
    printf '  %-18s %s\n' 'HSM user PIN:' "${hsm_user_pin:-not available yet}"
    printf '  %-18s %s\n' 'PKCS#11 module:' "$LOCAL_HSM_CONTAINER_MODULE_PATH"
  fi
  if ! $STATUS_ONLY; then
    if state_has monitoring; then
      if summary_trustpoint_auto_setup; then
        printf '  %-18s %s\n' 'Metrics:' 'enabled (/prometheus/metrics)'
      else
        printf '  %-18s %s\n' 'Metrics:' 'provisioned; enable after Trustpoint setup'
      fi
    fi
    printf '  %-18s %s\n' 'Env overlay:' "$ENV_OVERLAY"
    state_has sftp && printf '  %-18s %s\n' 'SFTPGo login:' "${SFTPGO_ADMIN_USER} / $(mask "$SFTPGO_ADMIN_PASSWORD")"
    if [[ " ${SERVICES[*]} " == *' monitoring '* ]]; then
      printf '  %-18s %s\n' 'Grafana login:' "${GRAFANA_ADMIN_USER} / $(mask "$GRAFANA_ADMIN_PASSWORD")"
    fi
  fi
  printf '\n'
}
