sftpgo_prompt_config(){
  EN_SFTPGO=$(ask_yes_no "Enable SFTPGo (demo SFTP + Web UI)?" "n" && echo true || echo false)
  if $EN_SFTPGO; then
    SFTPGO_SFTP_PORT="$(ask_free_port 'SFTPGo SFTP host port' "$SFTPGO_SFTP_PORT")"
    SFTPGO_WEB_PORT="$(ask_free_port 'SFTPGo Web UI host port' "$SFTPGO_WEB_PORT")"
    SFTPGO_ADMIN_USER="$(ask_user 'SFTPGo admin user' "$SFTPGO_ADMIN_USER")"
    SFTPGO_ADMIN_PASS="$(ask_password 'SFTPGo admin password' "$SFTPGO_ADMIN_PASS")"

    # Mandatory backup user
    ask_user "SFTPGo backup username" "$SFTPGO_BACKUP_USER"; SFTPGO_BACKUP_USER="$REPLY"
    ask_password "SFTPGo backup password" "$SFTPGO_BACKUP_PASS"; SFTPGO_BACKUP_PASS="$REPLY"
    SFTPGO_BACKUP_HOME="/srv/sftpgo/data/${SFTPGO_BACKUP_USER}"
    ask "SFTPGo backup home (inside container)" "$SFTPGO_BACKUP_HOME"; SFTPGO_BACKUP_HOME="$REPLY"
  fi
}

start_sftpgo(){
  $EN_SFTPGO || return 0
  local name="sftpgo"
  stop_one "$name"

  if port_in_use "$SFTPGO_SFTP_PORT"; then die "Host port ${SFTPGO_SFTP_PORT} in use (SFTPGo SFTP)."; fi
  if port_in_use "$SFTPGO_WEB_PORT"; then die "Host port ${SFTPGO_WEB_PORT} in use (SFTPGo Web)."; fi

  mkdir -p "${SFTPGO_ROOT}/data"
  if [[ -n "$SFTPGO_BACKUP_USER" ]]; then
    mkdir -p "${SFTPGO_ROOT}/data/${SFTPGO_BACKUP_USER}"
  fi
  chown -R 1000:1000 "${SFTPGO_ROOT}" 2>/dev/null || true

  log "Starting SFTPGo with auto-created admin..."
  docker run -d --name "$name" --network "$NET" \
    -p "${SFTPGO_SFTP_PORT}:2022" \
    -p "${SFTPGO_WEB_PORT}:8080" \
    -v "${SFTPGO_ROOT}:/srv/sftpgo" \
    -e SFTPGO_DATA_PROVIDER__CREATE_DEFAULT_ADMIN=true \
    -e SFTPGO_DEFAULT_ADMIN_USERNAME="$SFTPGO_ADMIN_USER" \
    -e SFTPGO_DEFAULT_ADMIN_PASSWORD="$SFTPGO_ADMIN_PASS" \
    -e SFTPGO_HTTPD__BINDINGS__0__ADDRESS="0.0.0.0" \
    -e SFTPGO_HTTPD__BINDINGS__0__ENABLE_REST_API=true \
    -e SFTPGO_HTTPD__BINDINGS__0__ENABLE_WEB_ADMIN=true \
    -e SFTPGO_HTTPD__BINDINGS__0__PORT=8080 \
    -e SFTPGO_SFTPD__BINDINGS__0__PORT=2022 \
    "$SFTPGO_IMAGE" >/dev/null
}


await_sftpgo_ready(){
  $EN_SFTPGO || return 0
  local PORT; PORT="$(sftpgo_web_port)"
  echo "Waiting (<= ${READINESS_TIMEOUT}s) for SFTPGo API on localhost:${PORT} ..."
  local until=$(( $(date +%s) + READINESS_TIMEOUT ))
  while (( $(date +%s) < until )); do
    if have curl && [[ "$(curl -fsS "http://127.0.0.1:${PORT}/healthz" 2>/dev/null || true)" == "ok" ]]; then
      ok "SFTPGo API healthy on :${PORT}"
      return 0
    fi
    if tcp_check 127.0.0.1 "$PORT" 1; then
      ok "SFTPGo API port open on :${PORT}"
      return 0
    fi
    printf "."; sleep 1
  done
  echo
  warn "SFTPGo API not confirmed after ${READINESS_TIMEOUT}s"
}


upsert_virtual_folder(){
  local vf_name="$1" mapped="$2"
  read -r -d '' VF_PAYLOAD <<JSON || true
{
  "name": "${vf_name}",
  "mapped_path": "${mapped}"
}
JSON
  local http
  http="$(curl -sS -o >(cat >/tmp/sftpgo_vf_upsert.json) -w '%{http_code}' \
    -X POST "${HDR[@]}" -d "$VF_PAYLOAD" "${API}/api/v2/folders")" || true
  if [[ "$http" != "200" && "$http" != "201" ]]; then
    http="$(curl -sS -o >(cat >/tmp/sftpgo_vf_upsert.json) -w '%{http_code}' \
      -X PUT "${HDR[@]}" -d "$VF_PAYLOAD" "${API}/api/v2/folders/${vf_name}")" || true
  fi
  if [[ "$http" != "200" && "$http" != "201" ]]; then
    warn "Virtual folder upsert failed (HTTP ${http}). Response follows:"
    cat /tmp/sftpgo_vf_upsert.json >&2
    return 1
  fi
  ok "Virtual folder '${vf_name}' → '${mapped}' ready."
}


provision_sftpgo_backup_user(){
  $EN_SFTPGO || return 0
  have curl || { warn "curl not found on host; skipping SFTPGo user provisioning."; return 0; }

  [[ -z "${SFTPGO_BACKUP_HOME:-}" ]] && SFTPGO_BACKUP_HOME="/srv/sftpgo/data/${SFTPGO_BACKUP_USER}"

  local host_home="${SFTPGO_ROOT}${SFTPGO_BACKUP_HOME#/srv/sftpgo}"
  mkdir -p "$host_home"
  chown -R 1000:1000 "$host_home" 2>/dev/null || true

  local PORT; PORT="$(sftpgo_web_port)"
  API="http://127.0.0.1:${PORT}"

  for _ in {1..30}; do
    [[ "$(curl -fsS "${API}/healthz" 2>/dev/null || true)" == "ok" ]] && break
    sleep 1
  done

  local token=""
  for _ in 1 2 3; do
    token="$(curl -fsS -u "${SFTPGO_ADMIN_USER}:${SFTPGO_ADMIN_PASS}" "${API}/api/v2/token" \
              | sed -nE 's/.*"access_token":"([^"]+)".*/\1/p')" || true
    [[ -n "$token" ]] && break
    sleep 1
  done
  [[ -n "$token" ]] || { warn "Could not obtain SFTPGo admin token; skipping user provisioning."; return 0; }

  HDR=(-H "Authorization: Bearer ${token}" -H "Content-Type: application/json")
  upsert_virtual_folder "trustpoint" "${SFTPGO_BACKUP_HOME}" || return 0

  local code method url http
  code="$(curl -s -o /dev/null -w '%{http_code}' "${HDR[@]}" "${API}/api/v2/users/${SFTPGO_BACKUP_USER}")"
  if [[ "$code" == "200" ]]; then
    method=PUT; url="${API}/api/v2/users/${SFTPGO_BACKUP_USER}"
  else
    method=POST; url="${API}/api/v2/users"
  fi

  read -r -d '' payload <<JSON || true
{
  "username": "${SFTPGO_BACKUP_USER}",
  "status": 1,
  "password": "${SFTPGO_BACKUP_PASS}",
  "home_dir": "${SFTPGO_BACKUP_HOME}",
  "permissions": { "/": ["*"] },
  "virtual_folders": [
    { "name": "trustpoint", "virtual_path": "/upload" }
  ]
}
JSON

  http="$(curl -sS -o >(cat >/tmp/sftpgo_user_upsert.json) -w '%{http_code}' \
    -X "$method" "${HDR[@]}" -d "$payload" "$url")" || true

  if [[ "$http" != "200" && "$http" != "201" ]]; then
    warn "User upsert failed (HTTP ${http}). Response follows:"
    cat /tmp/sftpgo_user_upsert.json >&2
  else
    ok "SFTPGo user '${SFTPGO_BACKUP_USER}' provisioned; VF mounted at /upload."
  fi
}

# ---- TLS fingerprint wait ----------------------------------------------------
