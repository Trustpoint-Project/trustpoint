step_enable_trustpoint(){ EN_APP=$(ask_yes_no "Enable trustpoint application container?" "y" && echo true || echo false); }


step_trustpoint_source(){
  $EN_APP || return 0
  if ask_yes_no "Build trustpoint locally from ${TP_DOCKERFILE}? (No = pull from Docker Hub)" "y"; then
    BUILD_LOCAL=true
    APP_IMAGE="trustpoint:local"
  else
    BUILD_LOCAL=false
    ask "Docker Hub image tag to pull (repository ${TP_REPO})" "latest"; local tag="$REPLY"
    APP_IMAGE="${TP_REPO}:${tag}"
  fi
}


step_app_db_binding(){
  $EN_APP || return 0
  if ask_yes_no "Should trustpoint reuse the PostgreSQL settings configured above?" "y"; then
    APP_DB_NAME="$DB_NAME"
    APP_DB_USER="$DB_USER"
    APP_DB_PASS="$DB_PASS"
    if $DB_INTERNAL; then
      # Internal DB: always connect to the container directly
      APP_DB_HOST="$DEF_DB_HOST_INTERNAL"
      APP_DB_PORT=5432
    else
      # External DB: use exactly what you entered
      APP_DB_HOST="$DB_HOST"
      APP_DB_PORT="$DB_PORT"
    fi
  else
    local def_host def_port
    if $DB_INTERNAL; then
      def_host="$DEF_DB_HOST_INTERNAL"; def_port=5432
    else
      def_host="$DB_HOST"; def_port="$DB_PORT"
    fi
    APP_DB_HOST="$(ask 'trustpoint DB host' "$def_host"; echo "$REPLY")"
    APP_DB_PORT="$(ask_port 'trustpoint DB port' "$def_port")"
    APP_DB_NAME="$(ask_dbname 'trustpoint DB name' "$DB_NAME")"
    APP_DB_USER="$(ask_user 'trustpoint DB user' "$DB_USER")"
    APP_DB_PASS="$(ask_password 'trustpoint DB password' "$DB_PASS")"
  fi
}


step_trustpoint_runtime_env(){
  $EN_APP || return 0

  ask "Trustpoint TLS DNS names (comma-separated, no protocol)" "$TP_TLS_DNS_NAMES_VALUE"
  TP_TLS_DNS_NAMES_VALUE="$REPLY"

  ask "Trustpoint TLS IPv4 addresses (comma-separated, optional)" "$TP_TLS_IPV4_ADDRESSES_VALUE"
  TP_TLS_IPV4_ADDRESSES_VALUE="$REPLY"

  ask "Trustpoint TLS IPv6 addresses (comma-separated, optional)" "$TP_TLS_IPV6_ADDRESSES_VALUE"
  TP_TLS_IPV6_ADDRESSES_VALUE="$REPLY"

  if ask_yes_no "Skip trustpoint in-app setup wizard using ${TRUSTPOINT_SKIP_SETUP_ENV_KEY}?" "n"; then
    TP_SKIP_SETUP_VALUE="true"
  else
    TP_SKIP_SETUP_VALUE="false"
  fi
}


build_trustpoint_image(){ [[ -f "$TP_DOCKERFILE" ]] || log "Dockerfile not found: $TP_DOCKERFILE"; log "Building trustpoint image..."; docker build -f "$TP_DOCKERFILE" -t "trustpoint:local" .; }

pull_trustpoint_image(){ log "Pulling ${APP_IMAGE} ..."; docker pull "${APP_IMAGE}" >/dev/null; }

configure_app_image_prompt(){
  if ask_yes_no "Build trustpoint locally from ${TP_DOCKERFILE}? (No = pull from Docker Hub)" "y"; then
    BUILD_LOCAL=true
    APP_IMAGE="trustpoint:local"
  else
    BUILD_LOCAL=false
    ask "Docker Hub image tag to pull (repository ${TP_REPO})" "latest"
    local tag="$REPLY"
    APP_IMAGE="${TP_REPO}:${tag}"
  fi
}

resolve_app_image(){
  if ! $EN_APP && ! $EN_WF2_WORKER; then
    return 0
  fi
  if $BUILD_LOCAL; then
    build_trustpoint_image
  else
    pull_trustpoint_image
  fi
}

start_app(){
  $EN_APP || return 0
  local name="trustpoint"
  stop_one "$name"
  # die early if 80/443 are busy
  if port_in_use "$APP_HTTP_HOST"; then die "Host port ${APP_HTTP_HOST} is in use (trustpoint HTTP)."; fi
  if port_in_use "$APP_HTTPS_HOST"; then die "Host port ${APP_HTTPS_HOST} is in use (trustpoint HTTPS)."; fi

  log "Starting trustpoint..."
  local env_file_arg=() wizard_env_target
  wizard_env_target="$(tp_wizard_env_target)"
  [[ -f "$ENV_FILE" ]] && env_file_arg+=( --env-file "$ENV_FILE" )
  if [[ "$wizard_env_target" != "$ENV_FILE" && -f "$wizard_env_target" ]]; then
    env_file_arg+=( --env-file "$wizard_env_target" )
  fi

  local smtp_env=()
  if $EN_MAILPIT; then
    smtp_env+=( -e "EMAIL_HOST=mailpit" -e "EMAIL_PORT=1025" -e "EMAIL_USE_TLS=0" -e "EMAIL_USE_SSL=0" -e "DEFAULT_FROM_EMAIL=no-reply@trustpoint.local" )
  fi

  local skip_env=() skip_key
  for skip_key in $TRUSTPOINT_SKIP_SETUP_ENV_KEYS; do
    [[ -n "$skip_key" ]] || continue
    skip_env+=( -e "${skip_key}=${TP_SKIP_SETUP_VALUE}" )
  done
  if [[ "$TP_SKIP_SETUP_VALUE" == "true" ]]; then
    skip_env+=(
      -e "TP_ADMIN_USERNAME=${TP_ADMIN_USERNAME_VALUE}"
      -e "TP_ADMIN_PASSWORD=${TP_ADMIN_PASSWORD_VALUE}"
      -e "TP_ADMIN_EMAIL=${TP_ADMIN_EMAIL_VALUE}"
      -e "TP_INJECT_DEMO_DATA=${TP_INJECT_DEMO_DATA_VALUE}"
    )
  fi

  docker run -d --name "$name" --network "$NET" \
    -p "${APP_HTTP_HOST}:80" \
    -p "${APP_HTTPS_HOST}:443" \
    "${env_file_arg[@]}" \
    -e "POSTGRES_DB=$APP_DB_NAME" \
    -e "DATABASE_USER=$APP_DB_USER" \
    -e "DATABASE_PASSWORD=$APP_DB_PASS" \
    -e "DATABASE_HOST=$APP_DB_HOST" \
    -e "DATABASE_PORT=$APP_DB_PORT" \
    -e "TP_HTTP_PORT=$APP_HTTP_HOST" \
    -e "TP_HTTPS_PORT=$APP_HTTPS_HOST" \
    -e "TP_TLS_DNS_NAMES=$TP_TLS_DNS_NAMES_VALUE" \
    -e "TP_TLS_IPV4_ADDRESSES=$TP_TLS_IPV4_ADDRESSES_VALUE" \
    -e "TP_TLS_IPV6_ADDRESSES=$TP_TLS_IPV6_ADDRESSES_VALUE" \
    "${skip_env[@]}" \
    "${smtp_env[@]}" \
    "$APP_IMAGE" >/dev/null
}


extract_tls_fingerprint_once(){
  local logs="$1"
  if [[ "$logs" =~ ([0-9A-Fa-f]{2}:){31}[0-9A-Fa-f]{2} ]]; then TLS_FP_FOUND="${BASH_REMATCH[0]}"; return 0; fi
  if [[ "$logs" =~ ([0-9A-Fa-f]{64}) ]]; then TLS_FP_FOUND="${BASH_REMATCH[1]}"; return 0; fi
  if [[ "$logs" =~ [Ss][Hh][Aa]-?256[:\ ]([A-Za-z0-9+/=_:-]{43,}) ]]; then TLS_FP_FOUND="SHA256:${BASH_REMATCH[1]}"; return 0; fi
  return 1
}


wait_tls_fingerprint(){
  $EN_APP || { TLS_FP_ELAPSED=0; return 0; }
  local start; start="$(date +%s)"
  local start_iso; start_iso="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  local end=$(( start + TLS_FP_TIMEOUT ))
  while (( $(date +%s) < end )); do
    local chunk
    chunk="$(docker logs --since "$start_iso" trustpoint 2>/dev/null || true)"
    if extract_tls_fingerprint_once "$chunk"; then
      TLS_FP_ELAPSED=$(( $(date +%s) - start ))
      return 0
    fi
    sleep 3
  done
  TLS_FP_ELAPSED=$(( $(date +%s) - start ))
  return 1
}
