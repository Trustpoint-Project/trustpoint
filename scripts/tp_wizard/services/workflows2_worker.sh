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
TRUSTPOINT_SERVICE_ROLE=worker
WORKFLOWS2_WORKER_ID=${WF2_WORKER_NAME}
WORKFLOWS2_WORKER_LEASE=${WF2_WORKER_LEASE}
WORKFLOWS2_WORKER_BATCH=${WF2_WORKER_BATCH}
WORKFLOWS2_WORKER_SLEEP=${WF2_WORKER_SLEEP}
DEFAULT_FROM_EMAIL=no-reply@trustpoint.local
EOF2

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
  docker run -d --name "$name" --network "$NET" \
    --env-file "$WF2_WORKER_ENV_FILE" \
    "$APP_IMAGE" >/dev/null
}

# -------------------------- Readiness & Provision -----------------------------
