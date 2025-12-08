#!/usr/bin/env bash
# tp_wizard.sh — single-file wizard for trustpoint stack
set -euo pipefail

# -------------------------- Constants & defaults ------------------------------
PROJECT="trustpoint"
NET="${PROJECT}-net"
VOL_DB="${PROJECT}_postgres_data"

# trustpoint image handling
TP_DOCKERFILE="docker/trustpoint/Dockerfile"
TP_REPO="trustpointproject/trustpoint"
APP_IMAGE="${TP_REPO}:latest"   # overridden to trustpoint:local when BUILD_LOCAL=true
BUILD_LOCAL=false

# Fixed images
PG_IMAGE="postgres:15.14"
MAILPIT_IMAGE="axllent/mailpit:v1.27"
SFTPGO_IMAGE="drakkan/sftpgo:2.6.x-slim"

# Fixed trustpoint ports
APP_HTTP_HOST=80
APP_HTTPS_HOST=443

# PostgreSQL defaults
DEF_DB_NAME="trustpoint_db"
DEF_DB_USER="admin"
DEF_DB_PASS="testing321"
DEF_DB_PORT=5432
DEF_DB_HOST_INTERNAL="postgres"   # container name/hostname

# Mailpit defaults
DEF_MAILPIT_SMTP_PORT=1025
DEF_MAILPIT_UI_PORT=8025

# SFTPGo defaults
DEF_SFTPGO_SFTP_PORT=2222
DEF_SFTPGO_WEB_PORT=8080
DEF_SFTPGO_ADMIN_USER="admin"
DEF_SFTPGO_ADMIN_PASS="testing321"
SFTPGO_ROOT="${PWD}/sftpgo-data"

# Timeouts
READINESS_TIMEOUT=90
TLS_FP_TIMEOUT=150

# Optional backup user provisioning
SFTPGO_BACKUP_USER="tpbackup"
SFTPGO_BACKUP_PASS="testing321"
SFTPGO_BACKUP_HOME=""

# -------------------------- UI helpers ---------------------------------------
bold(){ tput bold 2>/dev/null || true; }
rst(){ tput sgr0 2>/dev/null || true; }
ylw(){ tput setaf 3 2>/dev/null || true; }
grn(){ tput setaf 2 2>/dev/null || true; }
red(){ tput setaf 1 2>/dev/null || true; }
log(){ printf "%s\n" "$*" >&2; }
ok(){ log "$(grn)✔$(rst) $*"; }
warn(){ log "$(ylw)⚠$(rst) $*"; }
err(){ log "$(red)✖$(rst) $*"; }
die(){ err "$*"; exit 1; }
have(){ command -v "$1" >/dev/null 2>&1; }

# -------------------------- Docker helpers -----------------------------------
exists(){ docker ps -a --format '{{.Names}}' | grep -Fxq "$1"; }
running(){ docker ps --format '{{.Names}}' | grep -Fxq "$1"; }
ensure_network(){ docker network inspect "$NET" >/dev/null 2>&1 || docker network create "$NET" >/dev/null; }
ensure_volumes(){ docker volume inspect "$VOL_DB" >/dev/null 2>&1 || docker volume create "$VOL_DB" >/dev/null; }
stop_one(){ local n="$1"; exists "$n" || return 0; running "$n" && docker stop "$n" >/dev/null || true; docker rm "$n" >/dev/null || true; }

# quick TCP connect test (true if something accepts on host:port)
tcp_check(){ local host="$1" port="$2" ts=$(( $(date +%s) + ${3:-5} )); while (( $(date +%s) < ts )); do (exec 3<>"/dev/tcp/$host/$port") >/dev/null 2>&1 && { exec 3>&- 3<&-; return 0; }; sleep 1; done; return 1; }
port_in_use(){ tcp_check 127.0.0.1 "$1" 1; }

# SFTPGo host web port resolver (avoid Apache :80)
sftpgo_web_port(){
  local p; p="$(docker port sftpgo 8080/tcp 2>/dev/null | awk -F: '{print $2}')" || true
  echo "${p:-$SFTPGO_WEB_PORT}"
}

# -------------------------- Input helpers ------------------------------------
ask(){ local prompt="$1" def="${2:-}"; if [[ -n "$def" ]]; then read -r -p "$(bold)${prompt}$(rst) [default: ${def}] > " REPLY || true; REPLY="${REPLY:-$def}"; else read -r -p "$(bold)${prompt}$(rst) > " REPLY || true; fi; }
ask_yes_no(){ local prompt="$1" def="${2:-y}" a; case "${def}" in y|yes) a="[Y/n]";; n|no) a="[y/N]";; *) a="[y/n]";; esac; read -r -p "$(bold)${prompt} ${a}$(rst) > " resp || true; resp="${resp:-$def}"; [[ "${resp}" =~ ^y ]]; }
ask_port(){ local prompt="$1" def="$2" p; while true; do ask "$prompt" "$def"; p="$REPLY"; [[ "$p" =~ ^[0-9]{1,5}$ ]] && (( p>0 && p<65536 )) && { echo "$p"; return; } ; warn "Invalid port. Enter 1..65535."; done; }
ask_free_port(){ local prompt="$1" def="$2" p; while true; do p="$(ask_port "$prompt" "$def")"; if port_in_use "$p"; then warn "Port ${p} is already in use on this host. Pick another."; else echo "$p"; return; fi; done; }
ask_user(){ local prompt="$1" def="$2" u; while true; do ask "$prompt" "$def"; u="$REPLY"; [[ "$u" =~ ^[A-Za-z0-9_][A-Za-z0-9._-]*$ ]] && { echo "$u"; return; } ; warn "Invalid username."; done; }
ask_dbname(){ local prompt="$1" def="$2" d; while true; do ask "$prompt" "$def"; d="$REPLY"; [[ "$d" =~ ^[A-Za-z0-9_-]+$ ]] && { echo "$d"; return; } ; warn "Invalid DB name."; done; }
ask_password(){ local prompt="$1" def="$2" pw; while true; do ask "$prompt" "$def"; pw="$REPLY"; (( ${#pw} >= 6 )) && { echo "$pw"; return; } ; warn "Password too short (min 6)."; done; }
mask(){ local s="$1" n=${#1}; (( n<=2 )) && { printf '%s' '**'; return; }; printf '%*s' $((n-2)) '' | tr ' ' '*'; printf '%s' "${s: -2}"; }

# -------------------------- Wizard state -------------------------------------
EN_APP=false; EN_PG=false; EN_MAILPIT=false; EN_SFTPGO=false

DB_INTERNAL=true
DB_HOST="$DEF_DB_HOST_INTERNAL"   # default host when internal
DB_PORT="$DEF_DB_PORT"            # host-mapped port for convenience access
DB_NAME="$DEF_DB_NAME"
DB_USER="$DEF_DB_USER"
DB_PASS="$DEF_DB_PASS"

APP_DB_HOST="$DB_HOST"
APP_DB_PORT="$DB_PORT"
APP_DB_NAME="$DB_NAME"
APP_DB_USER="$DB_USER"
APP_DB_PASS="$DEF_DB_PASS"

MAILPIT_SMTP_PORT="$DEF_MAILPIT_SMTP_PORT"
MAILPIT_UI_PORT="$DEF_MAILPIT_UI_PORT"

SFTPGO_SFTP_PORT="$DEF_SFTPGO_SFTP_PORT"
SFTPGO_WEB_PORT="$DEF_SFTPGO_WEB_PORT"
SFTPGO_ADMIN_USER="$DEF_SFTPGO_ADMIN_USER"
SFTPGO_ADMIN_PASS="$DEF_SFTPGO_ADMIN_PASS"

TLS_FP_FOUND=""
TLS_FP_ELAPSED=0

# CLI target flags
ONLY_APP=false; ONLY_DB=false; ONLY_MAIL=false; ONLY_SFTP=false
NOWAIT=false

# -------------------------- Steps --------------------------------------------
preflight(){ have docker || die "docker not found"; docker version >/dev/null || die "docker daemon not reachable"; }

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
    DB_PORT="$(ask_free_port 'PostgreSQL host port (mapped)' "$DB_PORT")"
  else
    DB_HOST="$(ask 'External DB host/IP' '127.0.0.1'; echo "$REPLY")"
    DB_PORT="$(ask_port 'External DB port' "$DB_PORT")"
    DB_NAME="$(ask_dbname 'External DB database name' "$DB_NAME")"
    DB_USER="$(ask_user 'External DB username' "$DB_USER")"
    DB_PASS="$(ask_password 'External DB password' "$DB_PASS")"
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

step_helpers(){
  EN_MAILPIT=$(ask_yes_no "Enable Mailpit (demo SMTP inbox)?" "n" && echo true || echo false)
  if $EN_MAILPIT; then
    MAILPIT_SMTP_PORT="$(ask_free_port 'Mailpit SMTP host port' "$MAILPIT_SMTP_PORT")"
    MAILPIT_UI_PORT="$(ask_free_port 'Mailpit UI host port' "$MAILPIT_UI_PORT")"
  fi

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

show_plan(){
  echo
  echo "==================== Configuration Summary (Planned) ===================="
  printf "%-22s %s\n" "Network:" "$NET"
  printf "%-22s %s\n" "DB Volume:" "$VOL_DB"
  echo
  printf "%-22s %s\n" "trustpoint enabled:" "$EN_APP"
  if $EN_APP; then
    if $BUILD_LOCAL; then
      printf "%-22s %s\n" "App image:" "Build local → trustpoint:local"
    else
      printf "%-22s %s\n" "App image:" "Pull → ${APP_IMAGE}"
    fi
    printf "%-22s %s\n" "Host ports:" "80→80 (HTTP), 443→443 (HTTPS)"
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
  fi
  echo
  printf "%-22s %s\n" "Mailpit enabled:" "$EN_MAILPIT"
  $EN_MAILPIT && printf "%-22s %s\n" "Mailpit ports:" "SMTP ${MAILPIT_SMTP_PORT}, UI ${MAILPIT_UI_PORT}"
  echo
  printf "%-22s %s\n" "SFTPGo enabled:" "$EN_SFTPGO"
  $EN_SFTPGO && {
    printf "%-22s %s\n" "SFTPGo ports:" "SFTP ${SFTPGO_SFTP_PORT}, Web ${SFTPGO_WEB_PORT}"
    printf "%-22s %s\n" "SFTPGo admin:" "${SFTPGO_ADMIN_USER} / $(mask "$SFTPGO_ADMIN_PASS")"
    printf "%-22s %s\n" "SFTP backup user:" "${SFTPGO_BACKUP_USER} / $(mask "$SFTPGO_BACKUP_PASS")"
    printf "%-22s %s\n" "Backup home:" "${SFTPGO_BACKUP_HOME}"
  }
  echo "========================================================================="
}

# -------------------------- Build/Pull & Start -------------------------------
build_trustpoint_image(){ [[ -f "$TP_DOCKERFILE" ]] || log "Dockerfile not found: $TP_DOCKERFILE"; log "Building trustpoint image..."; docker build -f "$TP_DOCKERFILE" -t "trustpoint:local" .; }
pull_trustpoint_image(){ log "Pulling ${APP_IMAGE} ..."; docker pull "${APP_IMAGE}" >/dev/null; }

start_postgres(){
  $DB_INTERNAL || return 0
  ensure_volumes
  local name="postgres"
  stop_one "$name"
  # safety: host port must still be free (non-interactive runs)
  if port_in_use "$DB_PORT"; then die "Host port ${DB_PORT} is already in use. Choose another port or stop the process using it."; fi
  log "Starting PostgreSQL..."
  docker run -d --name "$name" --network "$NET" \
    -p "${DB_PORT}:5432" \
    -v "${VOL_DB}:/var/lib/postgresql/data" \
    -e "POSTGRES_DB=$DB_NAME" \
    -e "POSTGRES_USER=$DB_USER" \
    -e "POSTGRES_PASSWORD=$DB_PASS" \
    "$PG_IMAGE" >/dev/null
}

start_mailpit(){
  $EN_MAILPIT || return 0
  local name="mailpit"
  stop_one "$name"
  if port_in_use "$MAILPIT_SMTP_PORT"; then die "Host port ${MAILPIT_SMTP_PORT} in use (Mailpit SMTP)."; fi
  if port_in_use "$MAILPIT_UI_PORT"; then die "Host port ${MAILPIT_UI_PORT} in use (Mailpit UI)."; fi
  log "Starting Mailpit..."
  docker run -d --name "$name" --network "$NET" \
    -p "${MAILPIT_SMTP_PORT}:1025" \
    -p "${MAILPIT_UI_PORT}:8025" \
    "$MAILPIT_IMAGE" >/dev/null
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

start_app(){
  $EN_APP || return 0
  local name="trustpoint"
  stop_one "$name"
  # die early if 80/443 are busy
  if port_in_use "$APP_HTTP_HOST"; then die "Host port ${APP_HTTP_HOST} is in use (trustpoint HTTP)."; fi
  if port_in_use "$APP_HTTPS_HOST"; then die "Host port ${APP_HTTPS_HOST} is in use (trustpoint HTTPS)."; fi

  log "Starting trustpoint..."
  local smtp_env=()
  if $EN_MAILPIT; then
    smtp_env+=( -e "EMAIL_HOST=mailpit" -e "EMAIL_PORT=1025" -e "EMAIL_USE_TLS=0" -e "EMAIL_USE_SSL=0" -e "DEFAULT_FROM_EMAIL=no-reply@trustpoint.local" )
  fi
  docker run -d --name "$name" --network "$NET" \
    -p "${APP_HTTP_HOST}:80" \
    -p "${APP_HTTPS_HOST}:443" \
    -e "POSTGRES_DB=$APP_DB_NAME" \
    -e "DATABASE_USER=$APP_DB_USER" \
    -e "DATABASE_PASSWORD=$APP_DB_PASS" \
    -e "DATABASE_HOST=$APP_DB_HOST" \
    -e "DATABASE_PORT=$APP_DB_PORT" \
    "${smtp_env[@]}" \
    "$APP_IMAGE" >/dev/null
}

# -------------------------- Readiness & Provision -----------------------------
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

await_readiness(){
  local deadline=$(( $(date +%s) + READINESS_TIMEOUT ))
  if $DB_INTERNAL; then
    echo "Waiting (<= ${READINESS_TIMEOUT}s) for PostgreSQL on localhost:${DB_PORT} ..."
    while (( $(date +%s) < deadline )); do
      if tcp_check 127.0.0.1 "$DB_PORT" 1; then ok "PostgreSQL ready on :$DB_PORT"; break; fi
      printf "."; sleep 1
    done
    echo
  fi
  if $EN_APP; then
    echo "Waiting (<= ${READINESS_TIMEOUT}s) for trustpoint HTTP on localhost:${APP_HTTP_HOST} ..."
    while (( $(date +%s) < deadline )); do
      if tcp_check 127.0.0.1 "$APP_HTTP_HOST" 1; then ok "trustpoint reachable on :$APP_HTTP_HOST"; break; fi
      printf "."; sleep 1
    done
    echo
  fi
  await_sftpgo_ready
}

# ---- SFTPGo provisioning via REST -------------------------------------------
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

# -------------------------- Summary ------------------------------------------
final_summary(){
  echo
  echo "========================= Runtime Summary (Actual) ======================="
  printf "%-22s %s\n" "Network:" "$NET"
  printf "%-22s %s\n" "Containers:" "$(docker ps --format '{{.Names}}' | grep -E '^(trustpoint|postgres|mailpit|sftpgo)$' || true)"
  echo
  if $EN_APP; then
    printf "%-22s %s\n" "trustpoint:" "http://localhost:80  |  https://localhost:443"
  fi
  if $DB_INTERNAL; then
    printf "%-22s %s\n" "PostgreSQL:" "tcp://localhost:${DB_PORT}  (container port 5432)"
  fi
  if $EN_APP; then
    printf "%-22s %s\n" "DB connect:" "host=${APP_DB_HOST} port=${APP_DB_PORT} db=${APP_DB_NAME} user=${APP_DB_USER} pass=$(mask "$APP_DB_PASS")"
  fi
  $EN_MAILPIT && printf "%-22s %s\n" "Mailpit UI:" "http://localhost:${MAILPIT_UI_PORT}  (SMTP :${MAILPIT_SMTP_PORT})"
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

# -------------------------- High-level orchestration -------------------------
wizard(){
  echo "$(bold)trustpoint Setup Wizard$(rst)"
  ensure_network
  step_enable_trustpoint
  step_trustpoint_source
  step_enable_postgres
  step_postgres_config
  step_app_db_binding
  step_helpers
  show_plan
  ask_yes_no "Proceed with these settings?" "y" || { warn "Aborted by user."; exit 1; }
  $DB_INTERNAL && ensure_volumes
  start_postgres
  start_mailpit
  start_sftpgo
  start_app
  $NOWAIT || await_readiness
  $NOWAIT || provision_sftpgo_backup_user
  $NOWAIT || wait_tls_fingerprint || true
  final_summary
}

# -------------------------- Service selection & CLI --------------------------
usage(){
  cat <<'EOF'
Commands:
  (no command)       Run interactive wizard
  up [demo|trustpoint|db|mail|sftp] [--nowait]
  down [demo|trustpoint|db|mail|sftp]
  logs [trustpoint|db|mail|sftp]
  nuke
  help

Also supported (legacy): --only trustpoint|db|mail|sftp|demo
EOF
}

map_only_to_flags(){
  case "$1" in
    demo)  ONLY_APP=true; ONLY_DB=true; ONLY_MAIL=true; ONLY_SFTP=true ;;
    trustpoint|app)  ONLY_APP=true ;;   # accept both names
    db)   ONLY_DB=true ;;
    mail) ONLY_MAIL=true ;;
    sftp) ONLY_SFTP=true ;;
    *) die "Unknown target: $1 (use trustpoint|db|mail|sftp|demo)";;
  esac
}

set_targets_from_args(){
  local any=false
  while [[ $# -gt 0 ]]; do
    case "$1" in
      demo|trustpoint|app|db|mail|sftp) map_only_to_flags "$1"; any=true; shift ;;
      --only) map_only_to_flags "${2:-}"; any=true; shift 2 ;;
      --nowait) NOWAIT=true; shift ;;
      *) die "Unknown option/target: $1" ;;
    esac
  done
  if ! $any; then ONLY_APP=true; ONLY_DB=true; fi
}

start_selected(){
  ensure_network
  if $ONLY_DB; then DB_INTERNAL=true; fi
  if $ONLY_APP; then
    EN_APP=true
    # If internal DB is (or will be) used, set app connection to container:5432
    if $DB_INTERNAL; then
      APP_DB_HOST="$DEF_DB_HOST_INTERNAL"; APP_DB_PORT=5432
    else
      APP_DB_HOST="$DB_HOST"; APP_DB_PORT="$DB_PORT"
    fi
    APP_DB_NAME="$DB_NAME"; APP_DB_USER="$DB_USER"; APP_DB_PASS="$DB_PASS"
    # Prefer local image if present; otherwise pull repo:latest
    if ask_yes_no "Do you want to buid locally (No = pull from Docker Hub)" "y"; then
      if build_trustpoint_image; then
        BUILD_LOCAL=true
        APP_IMAGE="trustpoint:local"
      else
        warn "Local build failed"
        if ask_yes_no "Do you want to pull from Docker Hub" "y"; then
          BUILD_LOCAL=false
          APP_IMAGE="${TP_REPO}:latest"
          pull_trustpoint_image
        else
          nuke_cmd ;
          exit 1;
        fi
      fi
    else
      BUILD_LOCAL=false
      APP_IMAGE="${TP_REPO}:latest"
      pull_trustpoint_image
    fi
  fi
  $ONLY_DB   && { EN_PG=true; ensure_volumes; start_postgres; }
  $ONLY_MAIL && { EN_MAILPIT=true; start_mailpit; }
  $ONLY_SFTP && { EN_SFTPGO=true; start_sftpgo; }
  $ONLY_APP  && start_app

  $NOWAIT || await_readiness
  $NOWAIT || provision_sftpgo_backup_user
  $NOWAIT || wait_tls_fingerprint || true
  final_summary
}

down_selected(){
  local done=false
  $ONLY_APP   && stop_one trustpoint && done=true
  $ONLY_DB    && stop_one postgres   && done=true
  $ONLY_MAIL  && stop_one mailpit    && done=true
  $ONLY_SFTP  && stop_one sftpgo     && done=true
  $done || { stop_one trustpoint; stop_one postgres; stop_one mailpit; stop_one sftpgo; }
  ok "Stopped."
}

logs_selected(){
  local target="trustpoint"
  $ONLY_DB && target="postgres"
  $ONLY_MAIL && target="mailpit"
  $ONLY_SFTP && target="sftpgo"
  exists "$target" || die "Container not found: $target"
  docker logs -f "$target"
}

nuke_cmd(){
  read -r -p "Remove ALL project containers, network, and DB volume (and ./sftpgo-data)? [y/N] " a; [[ "${a}" == "y" ]] || exit 0
  read -r -p "Are you sure? This is destructive. [y/N] " b; [[ "${b}" == "y" ]] || exit 0
  stop_one trustpoint; stop_one postgres; stop_one mailpit; stop_one sftpgo
  docker network rm "$NET" >/dev/null 2>&1 || true
  docker volume rm "$VOL_DB" >/dev/null 2>&1 || true
  if [[ -d "$SFTPGO_ROOT" ]]; then rm -rf "$SFTPGO_ROOT"; fi
  ok "Project resources removed."
}

# -------------------------- Arg parsing & dispatch ----------------------------
preflight
ensure_network

cmd="${1:-}"
case "$cmd" in
  "" ) wizard ;;
  help) usage ;;
  up)
    shift || true
    set_targets_from_args "$@"
    start_selected
    ;;
  down)
    shift || true
    set_targets_from_args "$@"
    down_selected
    ;;
  logs)
    shift || true
    set_targets_from_args "$@"
    logs_selected
    ;;
  nuke) nuke_cmd ;;
  *) usage; die "Unknown command: $cmd" ;;
esac
