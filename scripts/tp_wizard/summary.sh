show_plan(){
  echo
  echo "==================== Configuration Summary (Planned) ===================="
  printf "%-22s %s\n" "Network:" "$NET"
  printf "%-22s %s\n" "Repo .env input:" "$ENV_FILE"
  printf "%-22s %s\n" "Wizard env output:" "$(tp_wizard_env_target)"
  printf "%-22s %s\n" "DB Volume:" "$VOL_DB"
  printf "%-22s %s\n" "Grafana Volume:" "$VOL_GRAFANA"
  echo
  printf "%-22s %s\n" "trustpoint enabled:" "$EN_APP"
  if $EN_APP; then
    if $BUILD_LOCAL; then
      printf "%-22s %s\n" "App image:" "Build local -> trustpoint:local"
    else
      printf "%-22s %s\n" "App image:" "Pull -> ${APP_IMAGE}"
    fi
    printf "%-22s %s\n" "Host ports:" "80->80 (HTTP), 443->443 (HTTPS)"
  fi
  echo
  printf "%-22s %s\n" "Internal Postgres:" "$DB_INTERNAL"
  printf "%-22s %s\n" "DB host:" "$DB_HOST"
  printf "%-22s %s\n" "DB host port:" "$DB_PORT"
  printf "%-22s %s\n" "DB name:" "$DB_NAME"
  printf "%-22s %s\n" "DB user:" "$DB_USER"
  printf "%-22s %s\n" "DB pass:" "$(mask "$DB_PASS")"
  echo
  if $EN_APP; then
    printf "%-22s %s\n" "trustpoint DB host:" "$APP_DB_HOST"
    printf "%-22s %s\n" "trustpoint DB port:" "$APP_DB_PORT"
    printf "%-22s %s\n" "trustpoint DB name:" "$APP_DB_NAME"
    printf "%-22s %s\n" "trustpoint DB user:" "$APP_DB_USER"
    printf "%-22s %s\n" "trustpoint DB pass:" "$(mask "$APP_DB_PASS")"
    printf "%-22s %s\n" "TLS DNS names:" "$TP_TLS_DNS_NAMES_VALUE"
    printf "%-22s %s\n" "TLS IPv4 addresses:" "${TP_TLS_IPV4_ADDRESSES_VALUE:-(none)}"
    printf "%-22s %s\n" "TLS IPv6 addresses:" "${TP_TLS_IPV6_ADDRESSES_VALUE:-(none)}"
    printf "%-22s %s\n" "Setup skipped:" "${TRUSTPOINT_SKIP_SETUP_ENV_KEY}=${TP_SKIP_SETUP_VALUE}"
  fi
  echo
  printf "%-22s %s\n" "Mailpit enabled:" "$EN_MAILPIT"
  $EN_MAILPIT && printf "%-22s %s\n" "Mailpit ports:" "SMTP ${MAILPIT_SMTP_PORT}, UI ${MAILPIT_UI_PORT}"
  echo
  printf "%-22s %s\n" "workflows2 worker:" "$EN_WF2_WORKER"
  $EN_WF2_WORKER && {
    printf "%-22s %s\n" "Worker container:" "${WF2_WORKER_NAME}"
    printf "%-22s %s\n" "workflow2 folder:" "${WF2_FOLDER}"
  }
  echo
  printf "%-22s %s\n" "SFTPGo enabled:" "$EN_SFTPGO"
  $EN_SFTPGO && {
    printf "%-22s %s\n" "SFTPGo ports:" "SFTP ${SFTPGO_SFTP_PORT}, Web ${SFTPGO_WEB_PORT}"
    printf "%-22s %s\n" "SFTPGo admin:" "${SFTPGO_ADMIN_USER} / $(mask "$SFTPGO_ADMIN_PASS")"
    printf "%-22s %s\n" "SFTP backup user:" "${SFTPGO_BACKUP_USER} / $(mask "$SFTPGO_BACKUP_PASS")"
    printf "%-22s %s\n" "Backup home:" "${SFTPGO_BACKUP_HOME}"
  }
  echo
  printf "%-22s %s\n" "Prometheus enabled:" "$EN_PROMETHEUS"
  $EN_PROMETHEUS && {
    printf "%-22s %s\n" "Prometheus UI:" "http://localhost:${PROMETHEUS_PORT}"
    printf "%-22s %s\n" "Prometheus config:" "$PROMETHEUS_CONFIG"
  }
  printf "%-22s %s\n" "Grafana enabled:" "$EN_GRAFANA"
  $EN_GRAFANA && {
    printf "%-22s %s\n" "Grafana UI:" "http://localhost:${GRAFANA_PORT}"
    printf "%-22s %s\n" "Grafana admin:" "${GRAFANA_ADMIN_USER} / $(mask "$GRAFANA_ADMIN_PASS")"
  }
  echo "========================================================================="
}

show_runtime_status(){
  local net_state="absent" vol_state="absent" grafana_vol_state="absent"
  docker network inspect "$NET" >/dev/null 2>&1 && net_state="present"
  docker volume inspect "$VOL_DB" >/dev/null 2>&1 && vol_state="present"
  docker volume inspect "$VOL_GRAFANA" >/dev/null 2>&1 && grafana_vol_state="present"

  echo
  echo "=========================== Runtime Status (Live) ========================"
  printf "%-22s %s\n" "Network:" "${NET} (${net_state})"
  printf "%-22s %s\n" "Repo .env input:" "$ENV_FILE"
  printf "%-22s %s\n" "Wizard env output:" "$(tp_wizard_env_target)"
  printf "%-22s %s\n" "DB volume:" "${VOL_DB} (${vol_state})"
  printf "%-22s %s\n" "Grafana volume:" "${VOL_GRAFANA} (${grafana_vol_state})"
  printf "%-22s %s\n" "workflow2 folder:" "$([ -d "$WF2_FOLDER" ] && echo "${WF2_FOLDER} (present)" || echo "${WF2_FOLDER} (absent)")"
  printf "%-22s %s\n" "Grafana provisioning:" "$([ -d "$GRAFANA_PROVISIONING_ROOT" ] && echo "${GRAFANA_PROVISIONING_ROOT} (present)" || echo "${GRAFANA_PROVISIONING_ROOT} (absent)")"
  echo
  printf "%-20s %-10s %-10s %s\n" "Container" "State" "Health" "Image"
  print_container_status_row trustpoint
  print_container_status_row postgres
  print_container_status_row mailpit
  print_container_status_row sftpgo
  print_container_status_row "$WF2_WORKER_NAME"
  print_container_status_row prometheus
  print_container_status_row grafana
  echo

  if exists trustpoint; then
    local http_port https_port db_host db_port db_name db_user db_pass tp_tls_dns_names tp_tls_ipv4_addresses tp_tls_ipv6_addresses tp_skip_setup
    http_port="$(container_host_port trustpoint 80/tcp)"
    https_port="$(container_host_port trustpoint 443/tcp)"
    db_host="$(container_env trustpoint DATABASE_HOST)"
    db_port="$(container_env trustpoint DATABASE_PORT)"
    db_name="$(container_env trustpoint POSTGRES_DB)"
    db_user="$(container_env trustpoint DATABASE_USER)"
    db_pass="$(container_env trustpoint DATABASE_PASSWORD)"
    tp_tls_dns_names="$(container_env trustpoint TP_TLS_DNS_NAMES)"
    tp_tls_ipv4_addresses="$(container_env trustpoint TP_TLS_IPV4_ADDRESSES)"
    tp_tls_ipv6_addresses="$(container_env trustpoint TP_TLS_IPV6_ADDRESSES)"
    tp_skip_setup="$(container_env trustpoint "$TRUSTPOINT_SKIP_SETUP_ENV_KEY")"

    [[ -n "$http_port" ]] && printf "%-22s %s\n" "trustpoint HTTP:" "http://localhost:${http_port}"
    [[ -n "$https_port" ]] && printf "%-22s %s\n" "trustpoint HTTPS:" "https://localhost:${https_port}"
    [[ -n "$tp_tls_dns_names" ]] && printf "%-22s %s\n" "TLS DNS names:" "${tp_tls_dns_names}"
    [[ -n "$tp_tls_ipv4_addresses" ]] && printf "%-22s %s\n" "TLS IPv4 addresses:" "${tp_tls_ipv4_addresses}"
    [[ -n "$tp_tls_ipv6_addresses" ]] && printf "%-22s %s\n" "TLS IPv6 addresses:" "${tp_tls_ipv6_addresses}"
    [[ -n "$tp_skip_setup" ]] && printf "%-22s %s\n" "Setup skipped:" "${TRUSTPOINT_SKIP_SETUP_ENV_KEY}=${tp_skip_setup}"
    printf "%-22s %s\n" "workflows2 mode:" "managed in Trustpoint settings"
    if [[ -n "$db_host" || -n "$db_port" || -n "$db_name" || -n "$db_user" ]]; then
      printf "%-22s %s\n" "DB connect:" "host=${db_host:-?} port=${db_port:-?} db=${db_name:-?} user=${db_user:-?} pass=$(mask "${db_pass:-}")"
    fi
  fi

  if exists postgres; then
    local pg_port
    pg_port="$(container_host_port postgres 5432/tcp)"
    [[ -n "$pg_port" ]] && printf "%-22s %s\n" "PostgreSQL:" "tcp://localhost:${pg_port}"
  fi

  if exists mailpit; then
    local mailpit_ui mailpit_smtp
    mailpit_ui="$(container_host_port mailpit 8025/tcp)"
    mailpit_smtp="$(container_host_port mailpit 1025/tcp)"
    [[ -n "$mailpit_ui" ]] && printf "%-22s %s\n" "Mailpit UI:" "http://localhost:${mailpit_ui}"
    [[ -n "$mailpit_smtp" ]] && printf "%-22s %s\n" "Mailpit SMTP:" "localhost:${mailpit_smtp}"
  fi

  if exists "$WF2_WORKER_NAME"; then
    local worker_db worker_lease worker_batch worker_sleep
    worker_db="$(container_env "$WF2_WORKER_NAME" DATABASE_HOST)"
    worker_lease="$(container_env "$WF2_WORKER_NAME" WORKFLOWS2_WORKER_LEASE)"
    worker_batch="$(container_env "$WF2_WORKER_NAME" WORKFLOWS2_WORKER_BATCH)"
    worker_sleep="$(container_env "$WF2_WORKER_NAME" WORKFLOWS2_WORKER_SLEEP)"
    printf "%-22s %s\n" "workflows2 worker:" "${WF2_WORKER_NAME}"
    [[ -n "$worker_db" ]] && printf "%-22s %s\n" "worker DB host:" "${worker_db}"
    [[ -n "$worker_lease" || -n "$worker_batch" || -n "$worker_sleep" ]] && \
      printf "%-22s %s\n" "worker tuning:" "lease=${worker_lease:-?} batch=${worker_batch:-?} sleep=${worker_sleep:-?}"
  fi

  if exists sftpgo; then
    local sftpgo_web sftpgo_sftp sftpgo_admin
    sftpgo_web="$(container_host_port sftpgo 8080/tcp)"
    sftpgo_sftp="$(container_host_port sftpgo 2022/tcp)"
    sftpgo_admin="$(container_env sftpgo SFTPGO_DEFAULT_ADMIN_USERNAME)"
    [[ -n "$sftpgo_web" ]] && printf "%-22s %s\n" "SFTPGo Web:" "http://localhost:${sftpgo_web}/web/admin"
    [[ -n "$sftpgo_sftp" ]] && printf "%-22s %s\n" "SFTPGo SFTP:" "sftp://localhost:${sftpgo_sftp}"
    [[ -n "$sftpgo_admin" ]] && printf "%-22s %s\n" "SFTPGo admin:" "${sftpgo_admin}"
    printf "%-22s %s\n" "SFTPGo data dir:" "${SFTPGO_ROOT}"
  fi

  if exists prometheus; then
    local prometheus_port
    prometheus_port="$(container_host_port prometheus 9090/tcp)"
    [[ -n "$prometheus_port" ]] && printf "%-22s %s\n" "Prometheus:" "http://localhost:${prometheus_port}"
    printf "%-22s %s\n" "Prometheus config:" "$PROMETHEUS_CONFIG"
  fi

  if exists grafana; then
    local grafana_port grafana_user
    grafana_port="$(container_host_port grafana 3000/tcp)"
    grafana_user="$(container_env grafana GF_SECURITY_ADMIN_USER)"
    [[ -n "$grafana_port" ]] && printf "%-22s %s\n" "Grafana:" "http://localhost:${grafana_port}"
    [[ -n "$grafana_user" ]] && printf "%-22s %s\n" "Grafana admin:" "${grafana_user}"
  fi

  echo "========================================================================="
}

final_summary(){
  echo
  echo "========================= Runtime Summary (Actual) ======================="
  printf "%-22s %s\n" "Network:" "$NET"
  printf "%-22s %s\n" "Repo .env input:" "$ENV_FILE"
  printf "%-22s %s\n" "Wizard env output:" "$(tp_wizard_env_target)"
  printf "%-22s %s\n" "Containers:" "$(docker ps --format '{{.Names}}' | grep -E '^(trustpoint|postgres|mailpit|sftpgo|trustpoint-worker|prometheus|grafana)$' || true)"
  echo
  if $EN_APP; then
    printf "%-22s %s\n" "trustpoint:" "http://localhost:${APP_HTTP_HOST}  |  https://localhost:${APP_HTTPS_HOST}"
    printf "%-22s %s\n" "TLS DNS names:" "$TP_TLS_DNS_NAMES_VALUE"
    printf "%-22s %s\n" "TLS IPv4 addresses:" "${TP_TLS_IPV4_ADDRESSES_VALUE:-(none)}"
    printf "%-22s %s\n" "TLS IPv6 addresses:" "${TP_TLS_IPV6_ADDRESSES_VALUE:-(none)}"
    printf "%-22s %s\n" "Setup skipped:" "${TRUSTPOINT_SKIP_SETUP_ENV_KEY}=${TP_SKIP_SETUP_VALUE}"
    printf "%-22s %s\n" "workflows2 mode:" "managed in Trustpoint settings (default: auto)"
  fi
  if $DB_INTERNAL; then
    printf "%-22s %s\n" "PostgreSQL:" "tcp://localhost:${DB_PORT}  (container port 5432)"
  fi
  if $EN_APP; then
    printf "%-22s %s\n" "DB connect:" "host=${APP_DB_HOST} port=${APP_DB_PORT} db=${APP_DB_NAME} user=${APP_DB_USER} pass=$(mask "$APP_DB_PASS")"
  fi
  $EN_MAILPIT && printf "%-22s %s\n" "Mailpit UI:" "http://localhost:${MAILPIT_UI_PORT}  (SMTP :${MAILPIT_SMTP_PORT})"
  if $EN_WF2_WORKER; then
    printf "%-22s %s\n" "workflows2 worker:" "${WF2_WORKER_NAME}"
    printf "%-22s %s\n" "workflow2 folder:" "${WF2_FOLDER}"
  fi
  if $EN_SFTPGO; then
    local PORT; PORT="$(sftpgo_web_port)"
    printf "%-22s %s\n" "SFTPGo Web:" "http://localhost:${PORT}/web/admin"
    printf "%-22s %s\n" "SFTPGo SFTP:" "sftp://localhost:${SFTPGO_SFTP_PORT}"
    printf "%-22s %s\n" "SFTPGo admin:" "${SFTPGO_ADMIN_USER} / $(mask "$SFTPGO_ADMIN_PASS")"
    printf "%-22s %s\n" "Backup user:" "${SFTPGO_BACKUP_USER} / $(mask "$SFTPGO_BACKUP_PASS")"
    printf "%-22s %s\n" "Backup home:" "${SFTPGO_BACKUP_HOME}"
    printf "%-22s %s\n" "Backup URL:" "sftp://${SFTPGO_BACKUP_USER}:***@127.0.0.1:${SFTPGO_SFTP_PORT}/"
    printf "%-22s %s\n" "Data dir:" "${SFTPGO_ROOT}"
  fi
  if $EN_PROMETHEUS; then
    printf "%-22s %s\n" "Prometheus:" "http://localhost:${PROMETHEUS_PORT}"
    printf "%-22s %s\n" "Prometheus config:" "$PROMETHEUS_CONFIG"
  fi
  if $EN_GRAFANA; then
    printf "%-22s %s\n" "Grafana:" "http://localhost:${GRAFANA_PORT}"
    printf "%-22s %s\n" "Grafana admin:" "${GRAFANA_ADMIN_USER} / $(mask "$GRAFANA_ADMIN_PASS")"
  fi
  if $EN_APP; then
    if [[ -n "$TLS_FP_FOUND" ]]; then
      printf "%-22s %s\n" "TLS fingerprint:" "$TLS_FP_FOUND"
    else
      if $NOWAIT; then
        printf "%-22s %s\n" "TLS fingerprint:" "skipped (NOWAIT)"
      else
        printf "%-22s %s\n" "TLS fingerprint:" "not found yet (polled ${TLS_FP_ELAPSED}s; timeout ${TLS_FP_TIMEOUT}s)"
      fi
    fi
  fi
  echo "========================================================================="
}
