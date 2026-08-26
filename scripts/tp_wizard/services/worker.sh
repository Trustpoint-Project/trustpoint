#!/usr/bin/env bash

start_worker() {
  remove_compose_service trustpoint-worker
  remove_container "$WF2_WORKER_NAME"
  start_container "$WF2_WORKER_NAME" -e TRUSTPOINT_PHASE=auto -e TRUSTPOINT_SERVICE_ROLE=worker \
    -e POSTGRES_DB="$DB_NAME" -e DATABASE_USER="$DB_USER" -e DATABASE_PASSWORD="$DB_PASS" \
    -e DATABASE_HOST="$APP_DB_HOST" -e DATABASE_PORT="$APP_DB_PORT" \
    -e WORKFLOWS2_WORKER_ID="$WF2_WORKER_ID" -e WORKFLOWS2_WORKER_LEASE="$WF2_WORKER_LEASE" \
    -e WORKFLOWS2_WORKER_BATCH="$WF2_WORKER_BATCH" -e WORKFLOWS2_WORKER_SLEEP="$WF2_WORKER_SLEEP" \
    "$APP_IMAGE"
  ok 'Workflows2 worker started'
}
