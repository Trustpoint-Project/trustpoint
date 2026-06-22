step_enable_postgres(){
  EN_PG=$(ask_yes_no "Start PostgreSQL container?" "y" && echo true || echo false)
  DB_INTERNAL=$EN_PG
  if $DB_INTERNAL; then DB_HOST="$DEF_DB_HOST_INTERNAL"; fi
}


step_postgres_config(){
  if $DB_INTERNAL; then
    DB_NAME="$(ask_dbname 'PostgreSQL database name' "$DB_NAME")"
    DB_USER="$(ask_user 'PostgreSQL username' "$DB_USER")"
    DB_PASS="$(ask_password 'PostgreSQL password' "$DB_PASS")"
    # Immediate check: host port must be free to publish
    DB_PORT="$(ask_free_port 'PostgreSQL host port (mapped, loopback only)' "$DB_PORT")"
  else
    DB_HOST="$(ask 'External DB host/IP' "$DB_HOST"; echo "$REPLY")"
    DB_PORT="$(ask_port 'External DB port' "$DB_PORT")"
    DB_NAME="$(ask_dbname 'External DB database name' "$DB_NAME")"
    DB_USER="$(ask_user 'External DB username' "$DB_USER")"
    DB_PASS="$(ask_password 'External DB password' "$DB_PASS")"
  fi
}


start_postgres(){
  $DB_INTERNAL || return 0
  ensure_volumes
  local name="postgres"
  stop_one "$name"
  # safety: host port must still be free (non-interactive runs)
  if port_in_use "$DB_PORT"; then die "Host port ${DB_PORT} is already in use. Choose another port or stop the process using it."; fi
  log "Starting PostgreSQL..."
  docker run -d --name "$name" --network "$NET"     -p "127.0.0.1:${DB_PORT}:5432"     -v "${VOL_DB}:/var/lib/postgresql/data"     -e "POSTGRES_DB=$DB_NAME"     -e "POSTGRES_USER=$DB_USER"     -e "POSTGRES_PASSWORD=$DB_PASS"     "$PG_IMAGE" >/dev/null
}
