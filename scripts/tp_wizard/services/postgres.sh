#!/usr/bin/env bash

start_postgres() {
  ensure_volume trustpoint_postgres_data
  remove_compose_service postgres
  remove_container postgres
  start_container postgres -p "127.0.0.1:${DB_PORT}:5432" -v trustpoint_postgres_data:/var/lib/postgresql/data \
    -e POSTGRES_USER="$DB_USER" -e POSTGRES_PASSWORD="$DB_PASS" -e POSTGRES_DB="$DB_NAME" "$PG_IMAGE"
  ok 'PostgreSQL started'
}
