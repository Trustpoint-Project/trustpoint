#!/usr/bin/env bash

start_worker() {
  remove_compose_service trustpoint-worker
  remove_container "$WF2_WORKER_NAME"
  start_container "$WF2_WORKER_NAME" -e TRUSTPOINT_PHASE=auto -e TRUSTPOINT_SERVICE_ROLE=worker \
    -e POSTGRES_DB="$DB_NAME" -e DATABASE_USER="$DB_USER" -e DATABASE_PASSWORD="$DB_PASS" \
    -e DATABASE_HOST=postgres -e DATABASE_PORT=5432 -e WORKFLOWS2_WORKER_ID="$WF2_WORKER_NAME" "$APP_IMAGE"
  ok 'Workflows2 worker started'
}
