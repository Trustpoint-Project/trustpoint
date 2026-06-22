# Shared orchestration used by wizard mode, demo mode, and CLI up mode.

await_readiness(){
  local deadline=$(( $(date +%s) + READINESS_TIMEOUT ))

  if $DB_INTERNAL; then
    echo "Waiting (<= ${READINESS_TIMEOUT}s) for PostgreSQL on localhost:${DB_PORT} ..."
    while (( $(date +%s) < deadline )); do
      if tcp_check 127.0.0.1 "$DB_PORT" 1; then
        ok "PostgreSQL ready on :$DB_PORT"
        break
      fi
      printf "."
      sleep 1
    done
    echo
  fi

  if $EN_APP; then
    echo "Waiting (<= ${READINESS_TIMEOUT}s) for trustpoint HTTP on localhost:${APP_HTTP_HOST} ..."
    while (( $(date +%s) < deadline )); do
      if tcp_check 127.0.0.1 "$APP_HTTP_HOST" 1; then
        ok "trustpoint reachable on :$APP_HTTP_HOST"
        break
      fi
      printf "."
      sleep 1
    done
    echo
  fi

  await_sftpgo_ready
  await_monitoring_ready
}

runtime_after_start(){
  $NOWAIT || await_readiness
  $NOWAIT || provision_sftpgo_backup_user
  $NOWAIT || verify_mailpit_delivery
  $NOWAIT || wait_tls_fingerprint || true
  final_summary
}

runtime_start_enabled(){
  ensure_network
  sync_env_file
  resolve_app_image

  $DB_INTERNAL && ensure_volumes

  start_postgres
  start_mailpit
  start_sftpgo

  $EN_WF2_WORKER || stop_one "$WF2_WORKER_NAME"

  start_app
  start_workflows2_worker
  start_prometheus
  start_grafana

  runtime_after_start
}

runtime_start_selected(){
  $ONLY_APP && EN_APP=true
  $ONLY_DB && {
    EN_PG=true
    DB_INTERNAL=true
  }
  $ONLY_MAIL && EN_MAILPIT=true
  $ONLY_SFTP && EN_SFTPGO=true
  $ONLY_WF2_WORKER && EN_WF2_WORKER=true
  $ONLY_PROMETHEUS && EN_PROMETHEUS=true
  $ONLY_GRAFANA && EN_GRAFANA=true

  ensure_network
  sync_env_file
  resolve_app_image

  $ONLY_DB && {
    ensure_volumes
    start_postgres
  }

  $ONLY_MAIL && start_mailpit

  $ONLY_SFTP && start_sftpgo

  $EN_WF2_WORKER || {
    $ONLY_APP && stop_one "$WF2_WORKER_NAME"
  }

  $ONLY_APP && start_app

  $EN_WF2_WORKER && start_workflows2_worker

  $ONLY_PROMETHEUS && start_prometheus

  $ONLY_GRAFANA && start_grafana

  runtime_after_start
}
