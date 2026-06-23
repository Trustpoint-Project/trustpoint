# shellcheck shell=bash
# Compact, developer-friendly plan/status/summary output.

_tp_line(){
  printf '%s\n' '------------------------------------------------------------'
}

_tp_title(){
  echo
  printf '%s\n' "$(bold)$1$(rst)"
  _tp_line
}

_tp_kv(){
  local key="$1" value="$2"
  [[ -n "$value" ]] || return 0
  printf '  %-16s %s\n' "$key" "$value"
}

_tp_join_words(){
  local first=true item
  for item in "$@"; do
    if $first; then
      printf '%s' "$item"
      first=false
    else
      printf ', %s' "$item"
    fi
  done
}

_tp_env_summary(){
  local target
  target="$(tp_wizard_env_target)"
  if [[ "$target" == "$ENV_FILE" ]]; then
    printf '%s' "${ENV_FILE} (wizard writes here)"
  elif [[ -f "$ENV_FILE" ]]; then
    printf '%s' "${ENV_FILE} + ${target}"
  else
    printf '%s' "${target}"
  fi
}

_tp_enabled_services(){
  local services=()
  $EN_APP && services+=(trustpoint)
  $DB_INTERNAL && services+=(postgres)
  $EN_MAILPIT && services+=(mailpit)
  $EN_SFTPGO && services+=(sftpgo)
  $EN_WF2_WORKER && services+=(worker)
  $EN_PROMETHEUS && services+=(prometheus)
  $EN_GRAFANA && services+=(grafana)

  if ((${#services[@]} == 0)); then
    printf '%s' 'none'
  else
    _tp_join_words "${services[@]}"
  fi
}

_tp_app_urls_from_state(){
  local urls=()
  $EN_APP || return 0
  urls+=("http://localhost:${APP_HTTP_HOST}")
  urls+=("https://localhost:${APP_HTTPS_HOST}")
  _tp_join_words "${urls[@]}"
}

_tp_status_text(){
  local state="$1" health="${2:-}"
  case "$state" in
    absent) printf '%s' 'absent' ;;
    running)
      case "$health" in
        healthy) printf '%s' 'up/healthy' ;;
        starting) printf '%s' 'up/starting' ;;
        unhealthy) printf '%s' 'up/unhealthy' ;;
        -|'') printf '%s' 'up' ;;
        *) printf '%s' "up/${health}" ;;
      esac
      ;;
    exited|dead) printf '%s' 'stopped' ;;
    *) printf '%s' "$state" ;;
  esac
}

_tp_container_url(){
  local name="$1" port_spec="$2" scheme="$3" path="${4:-}"
  local port
  port="$(container_host_port "$name" "$port_spec")"
  [[ -n "$port" ]] || return 0
  printf '%s://localhost:%s%s' "$scheme" "$port" "$path"
}

_tp_live_trustpoint_urls(){
  local http_port https_port urls=()
  http_port="$(container_host_port trustpoint 80/tcp)"
  https_port="$(container_host_port trustpoint 443/tcp)"
  [[ -n "$http_port" ]] && urls+=("http://localhost:${http_port}")
  [[ -n "$https_port" ]] && urls+=("https://localhost:${https_port}")
  ((${#urls[@]} > 0)) && _tp_join_words "${urls[@]}"
}

_tp_live_sftpgo_urls(){
  local web_port sftp_port urls=()
  web_port="$(container_host_port sftpgo 8080/tcp)"
  sftp_port="$(container_host_port sftpgo 2022/tcp)"
  [[ -n "$web_port" ]] && urls+=("http://localhost:${web_port}/web/admin")
  [[ -n "$sftp_port" ]] && urls+=("sftp://localhost:${sftp_port}")
  ((${#urls[@]} > 0)) && _tp_join_words "${urls[@]}"
}

_tp_live_postgres_url(){
  local pg_port
  pg_port="$(container_host_port postgres 5432/tcp)"
  [[ -n "$pg_port" ]] && printf 'localhost:%s' "$pg_port"
}

_tp_runtime_row(){
  local name="$1" label="$2" url="$3"
  local state health status
  state="$(container_state "$name")"
  health="$(container_health "$name")"
  status="$(_tp_status_text "$state" "$health")"
  printf '  %-18s %-13s %s\n' "$label" "$status" "${url:--}"
}

_tp_runtime_rows(){
  printf '  %-18s %-13s %s\n' 'Service' 'Status' 'Access'
  printf '  %-18s %-13s %s\n' '-------' '------' '------'
  _tp_runtime_row trustpoint 'trustpoint' "$(_tp_live_trustpoint_urls)"
  _tp_runtime_row postgres 'postgres' "$(_tp_live_postgres_url)"
  _tp_runtime_row mailpit 'mailpit' "$(_tp_container_url mailpit 8025/tcp http)"
  _tp_runtime_row sftpgo 'sftpgo' "$(_tp_live_sftpgo_urls)"
  _tp_runtime_row "$WF2_WORKER_NAME" 'worker' '-'
  _tp_runtime_row prometheus 'prometheus' "$(_tp_container_url prometheus 9090/tcp http)"
  _tp_runtime_row grafana 'grafana' "$(_tp_container_url grafana 3000/tcp http)"
}

show_plan(){
  _tp_title 'trustpoint setup plan'
  _tp_kv 'services' "$(_tp_enabled_services)"
  _tp_kv 'env files' "$(_tp_env_summary)"

  if $EN_APP; then
    _tp_kv 'app' "$(_tp_app_urls_from_state)"
    _tp_kv 'image' "$($BUILD_LOCAL && printf 'build local -> trustpoint:local' || printf 'pull -> %s' "$APP_IMAGE")"
    _tp_kv 'database' "${APP_DB_USER}@${APP_DB_HOST}:${APP_DB_PORT}/${APP_DB_NAME}"
    _tp_kv 'setup skip' "${TRUSTPOINT_SKIP_SETUP_ENV_KEY}=${TP_SKIP_SETUP_VALUE}"
  fi

  $EN_MAILPIT && _tp_kv 'mailpit' "http://localhost:${MAILPIT_UI_PORT} (smtp ${MAILPIT_SMTP_PORT})"
  $EN_SFTPGO && _tp_kv 'sftpgo' "http://localhost:${SFTPGO_WEB_PORT}/web/admin, sftp ${SFTPGO_SFTP_PORT}"
  $EN_PROMETHEUS && _tp_kv 'prometheus' "http://localhost:${PROMETHEUS_PORT} -> ${TRUSTPOINT_METRICS_SCHEME_VALUE}://${TRUSTPOINT_METRICS_TARGET_VALUE}${TRUSTPOINT_METRICS_PATH_VALUE}"
  $EN_GRAFANA && _tp_kv 'grafana' "http://localhost:${GRAFANA_PORT} (${GRAFANA_ADMIN_USER} / $(mask "$GRAFANA_ADMIN_PASS"))"
  $EN_WF2_WORKER && _tp_kv 'worker' "$WF2_WORKER_NAME"

  _tp_line
}

show_runtime_status(){
  local net_state='absent' db_vol_state='absent' grafana_vol_state='absent'
  docker network inspect "$NET" >/dev/null 2>&1 && net_state='present'
  docker volume inspect "$VOL_DB" >/dev/null 2>&1 && db_vol_state='present'
  docker volume inspect "$VOL_GRAFANA" >/dev/null 2>&1 && grafana_vol_state='present'

  _tp_title 'trustpoint runtime status'
  _tp_runtime_rows
  echo
  _tp_kv 'network' "${NET} (${net_state})"
  _tp_kv 'env files' "$(_tp_env_summary)"
  _tp_kv 'volumes' "db=${db_vol_state}, grafana=${grafana_vol_state}"

  if exists trustpoint; then
    local db_host db_port db_name db_user setup_skip
    db_host="$(container_env trustpoint DATABASE_HOST)"
    db_port="$(container_env trustpoint DATABASE_PORT)"
    db_name="$(container_env trustpoint POSTGRES_DB)"
    db_user="$(container_env trustpoint DATABASE_USER)"
    setup_skip="$(container_env trustpoint "$TRUSTPOINT_SKIP_SETUP_ENV_KEY")"
    [[ -n "$db_host$db_port$db_name$db_user" ]] && _tp_kv 'database' "${db_user:-?}@${db_host:-?}:${db_port:-?}/${db_name:-?}"
    [[ -n "$setup_skip" ]] && _tp_kv 'setup skip' "${TRUSTPOINT_SKIP_SETUP_ENV_KEY}=${setup_skip}"
  fi

  _tp_line
}

final_summary(){
  _tp_title 'trustpoint stack ready'
  _tp_runtime_rows
  echo
  _tp_kv 'env files' "$(_tp_env_summary)"

  if $EN_APP; then
    _tp_kv 'database' "${APP_DB_USER}@${APP_DB_HOST}:${APP_DB_PORT}/${APP_DB_NAME}"
    _tp_kv 'setup skip' "${TRUSTPOINT_SKIP_SETUP_ENV_KEY}=${TP_SKIP_SETUP_VALUE}"
  fi

  if $EN_SFTPGO; then
    _tp_kv 'sftp admin' "${SFTPGO_ADMIN_USER} / $(mask "$SFTPGO_ADMIN_PASS")"
    _tp_kv 'backup user' "${SFTPGO_BACKUP_USER} / $(mask "$SFTPGO_BACKUP_PASS")"
  fi

  if $EN_PROMETHEUS; then
    _tp_kv 'metrics' "${TRUSTPOINT_METRICS_SCHEME_VALUE}://${TRUSTPOINT_METRICS_TARGET_VALUE}${TRUSTPOINT_METRICS_PATH_VALUE}"
  fi
  if $EN_GRAFANA; then
    _tp_kv 'grafana admin' "${GRAFANA_ADMIN_USER} / $(mask "$GRAFANA_ADMIN_PASS")"
    _tp_kv 'dashboard' "Grafana -> Dashboards -> Trustpoint -> Trustpoint Overview"
  fi

  if $EN_APP; then
    if [[ -n "$TLS_FP_FOUND" ]]; then
      _tp_kv 'tls fingerprint' "$TLS_FP_FOUND"
    elif ! $NOWAIT; then
      _tp_kv 'tls fingerprint' "not found after ${TLS_FP_ELAPSED}s"
    fi
  fi

  _tp_line
}
