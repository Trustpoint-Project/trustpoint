#!/usr/bin/env bash

runtime_wait() {
  $NOWAIT && return 0
  local service="$1" name timeout=90
  case "$service" in
    db) name=postgres ;; mail) name=mailpit ;; sftp) name=sftpgo ;;
    worker) name="$WF2_WORKER_NAME" ;; softhsm) name="$SOFTHSM_NAME" ;;
    prometheus) name="$PROMETHEUS_NAME" ;; grafana) name="$GRAFANA_NAME" ;;
    monitoring) runtime_wait prometheus; runtime_wait grafana; return ;;
    *) name="$service" ;;
  esac
  for ((i=0; i<timeout; i++)); do
    container_running "$name" && return 0
    sleep 1
  done
  warn "$name did not become ready within ${timeout}s"
}

runtime_start() {
  preflight
  ensure_network
  write_runtime_env
  local service
  for service in "${SERVICES[@]}"; do
    case "$service" in
      db) start_postgres ;;
      mail) start_mailpit ;;
      sftp) start_sftpgo ;;
      trustpoint) start_trustpoint ;;
      worker) start_worker ;;
      softhsm) start_softhsm ;;
      monitoring) start_monitoring ;;
      *) die "Unknown service: $service" ;;
    esac
  done
  for service in "${SERVICES[@]}"; do runtime_wait "$service"; done
}

runtime_stop() {
  preflight
  local service name
  for service in "$@"; do
    case "$service" in
      db) name=postgres; remove_compose_service postgres ;;
      mail) name=mailpit ;; sftp) name=sftpgo ;;
      trustpoint) name=trustpoint; remove_compose_service trustpoint ;;
      worker) name="$WF2_WORKER_NAME"; remove_compose_service trustpoint-worker ;;
      softhsm) name="$SOFTHSM_NAME" ;; prometheus) name="$PROMETHEUS_NAME" ;;
      grafana) name="$GRAFANA_NAME" ;; monitoring) runtime_stop prometheus grafana; continue ;;
      *) die "Unknown service: $service" ;;
    esac
    remove_container "$name"
  done
}
