step_workflows2_worker(){
  $EN_APP || return 0
  EN_WF2_WORKER=$(
    ask_yes_no "Delegate workflows2 tasks to a dedicated worker container?" "n" && echo true || echo false
  )
}


prepare_workflows2_worker_folder(){
  $EN_WF2_WORKER || return 0
  mkdir -p "$WF2_FOLDER"
  chmod 700 "$WF2_FOLDER" 2>/dev/null || true
  cat > "$WF2_WORKER_README" <<EOF2
This folder was created by tp_wizard.sh for the optional dedicated workflows2 worker.

Files:
- worker.env : environment passed to the worker container

Container:
- ${WF2_WORKER_NAME}
EOF2
  chmod 644 "$WF2_WORKER_README" 2>/dev/null || true

  cat > "$WF2_WORKER_ENV_FILE" <<EOF2
POSTGRES_DB=${APP_DB_NAME}
DATABASE_USER=${APP_DB_USER}
DATABASE_PASSWORD=${APP_DB_PASS}
DATABASE_HOST=${APP_DB_HOST}
DATABASE_PORT=${APP_DB_PORT}
TP_HTTP_PORT=${APP_HTTP_HOST}
TP_HTTPS_PORT=${APP_HTTPS_HOST}
TP_TLS_DNS_NAMES=${TP_TLS_DNS_NAMES_VALUE}
TP_TLS_IPV4_ADDRESSES=${TP_TLS_IPV4_ADDRESSES_VALUE}
TP_TLS_IPV6_ADDRESSES=${TP_TLS_IPV6_ADDRESSES_VALUE}
TRUSTPOINT_SERVICE_ROLE=worker
WORKFLOWS2_WORKER_ID=${WF2_WORKER_NAME}
WORKFLOWS2_WORKER_LEASE=${WF2_WORKER_LEASE}
WORKFLOWS2_WORKER_BATCH=${WF2_WORKER_BATCH}
WORKFLOWS2_WORKER_SLEEP=${WF2_WORKER_SLEEP}
DEFAULT_FROM_EMAIL=no-reply@trustpoint.local
EOF2

  local skip_key
  for skip_key in $TRUSTPOINT_SKIP_SETUP_ENV_KEYS; do
    [[ -n "$skip_key" ]] || continue
    printf '%s=%s\n' "$skip_key" "$TP_SKIP_SETUP_VALUE" >> "$WF2_WORKER_ENV_FILE"
  done
  if [[ "$TP_SKIP_SETUP_VALUE" == "true" ]]; then
    cat >> "$WF2_WORKER_ENV_FILE" <<EOF2
TP_ADMIN_USERNAME=${TP_ADMIN_USERNAME_VALUE}
TP_ADMIN_PASSWORD=${TP_ADMIN_PASSWORD_VALUE}
TP_ADMIN_EMAIL=${TP_ADMIN_EMAIL_VALUE}
TP_INJECT_DEMO_DATA=${TP_INJECT_DEMO_DATA_VALUE}
TP_ENABLE_PROMETHEUS_METRICS=${TP_ENABLE_PROMETHEUS_METRICS_VALUE}
EOF2
  fi

  if $EN_MAILPIT; then
    cat >> "$WF2_WORKER_ENV_FILE" <<EOF2
EMAIL_HOST=mailpit
EMAIL_PORT=1025
EMAIL_USE_TLS=0
EMAIL_USE_SSL=0
EOF2
  fi
  chmod 600 "$WF2_WORKER_ENV_FILE" 2>/dev/null || true
}


start_workflows2_worker(){
  $EN_WF2_WORKER || return 0
  local name="$WF2_WORKER_NAME"
  stop_one "$name"
  prepare_workflows2_worker_folder
  log "Starting dedicated workflows2 worker..."
  docker run -d --name "$name" --network "$NET"     --env-file "$WF2_WORKER_ENV_FILE"     "$APP_IMAGE" >/dev/null
}
