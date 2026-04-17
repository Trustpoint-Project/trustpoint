#!/usr/bin/env bash
# tp_wizard.sh — single-file wizard for trustpoint stack
set -euo pipefail

# -------------------------- Constants & defaults ------------------------------
PROJECT="trustpoint"
NET="${PROJECT}-net"
VOL_DB="${PROJECT}_postgres_data"

# trustpoint image handling
TP_DOCKERFILE="docker/trustpoint/Dockerfile"
HSM_DOCKERFILE="docker/softhsm/Dockerfile"
TP_REPO="trustpointproject/trustpoint"
APP_IMAGE="${TP_REPO}:latest"   # overridden to trustpoint:local when BUILD_LOCAL=true
SOFTHSM_IMAGE="trustpoint:softhsm-local"
BUILD_LOCAL=false

# Fixed images
PG_IMAGE="postgres:15.14"
MAILPIT_IMAGE="axllent/mailpit:v1.27"
SFTPGO_IMAGE="drakkan/sftpgo:2.6.x-slim"
WF2_WORKER_NAME="trustpoint-worker"
SOFTHSM_NAME="softhsm"

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
DEF_WF2_WORKER_LEASE=30
DEF_WF2_WORKER_BATCH=10
DEF_WF2_WORKER_SLEEP=1
MAILPIT_PROBE_TIMEOUT=20

# Local/dev SoftHSM defaults
LOCAL_HSM_ROOT="${PWD}/var/hsm"
LOCAL_HSM_CONFIG_DIR="${LOCAL_HSM_ROOT}/config"
LOCAL_HSM_LIB_DIR="${LOCAL_HSM_ROOT}/lib"
LOCAL_HSM_TOKEN_DIR="${LOCAL_HSM_ROOT}/tokens"
LOCAL_HSM_CONTAINER_ROOT="/var/lib/trustpoint/hsm"
LOCAL_HSM_CONTAINER_CONFIG_DIR="${LOCAL_HSM_CONTAINER_ROOT}/config"
LOCAL_HSM_CONTAINER_TOKEN_DIR="${LOCAL_HSM_CONTAINER_ROOT}/tokens"
LOCAL_HSM_TOKEN_LABEL="Trustpoint-SoftHSM"
LOCAL_HSM_PROFILE_NAME="local-dev-softhsm"
LOCAL_HSM_METADATA_FILE="${LOCAL_HSM_CONFIG_DIR}/local-dev-token.env"

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
ensure_volumes(){ docker volume inspect "$VOL_DB" >/dev/null 2>&1 || docker volume create --label "tp.project=${PROJECT}" "$VOL_DB" >/dev/null; }
stop_one(){ local n="$1"; exists "$n" || return 0; running "$n" && docker stop "$n" >/dev/null || true; docker rm "$n" >/dev/null || true; }
container_state(){ local n="$1"; exists "$n" || { echo "absent"; return; }; docker inspect -f '{{.State.Status}}' "$n" 2>/dev/null || echo "unknown"; }
container_health(){ local n="$1" h=""; exists "$n" || { echo "-"; return; }; h="$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{end}}' "$n" 2>/dev/null || true)"; echo "${h:--}"; }
container_image(){ local n="$1"; exists "$n" || { echo "-"; return; }; docker inspect -f '{{.Config.Image}}' "$n" 2>/dev/null || echo "-"; }
container_host_port(){ local n="$1" spec="$2" p=""; exists "$n" || return 0; p="$(docker port "$n" "$spec" 2>/dev/null | awk -F: 'NR==1 {print $NF}')" || true; echo "${p}"; }
container_env(){ local n="$1" key="$2"; exists "$n" || return 0; docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' "$n" 2>/dev/null | sed -n "s/^${key}=//p" | head -n1; }
container_volume_names(){
  local n="$1"
  exists "$n" || return 0
  docker inspect -f '{{range .Mounts}}{{if eq .Type "volume"}}{{println .Name}}{{end}}{{end}}' "$n" 2>/dev/null | sed '/^$/d'
}
collect_project_volumes(){
  {
    echo "$VOL_DB"
    container_volume_names trustpoint
    container_volume_names postgres
    container_volume_names mailpit
    container_volume_names sftpgo
    container_volume_names "$WF2_WORKER_NAME"
  } | sed '/^$/d' | sort -u
}
print_container_status_row(){
  local n="$1"
  printf "%-20s %-10s %-10s %s\n" "$n" "$(container_state "$n")" "$(container_health "$n")" "$(container_image "$n")"
}

fix_bind_mount_owner(){
  local dir="$1"
  [[ -d "$dir" ]] || return 0
  docker run --rm \
    -v "${dir}:/target" \
    debian:trixie-slim \
    bash -lc "chown -R $(id -u):$(id -g) /target"
}

purge_bind_mount_dir(){
  local dir="$1"
  [[ -d "$dir" ]] || return 0
  docker run --rm \
    -v "${dir}:/target" \
    debian:trixie-slim \
    bash -lc 'rm -rf /target/* /target/.[!.]* /target/..?* 2>/dev/null || true'
}

# quick TCP connect test (true if something accepts on host:port)
tcp_check(){ local host="$1" port="$2" ts=$(( $(date +%s) + ${3:-5} )); while (( $(date +%s) < ts )); do (exec 3<>"/dev/tcp/$host/$port") >/dev/null 2>&1 && { exec 3>&- 3<&-; return 0; }; sleep 1; done; return 1; }
port_in_use(){ tcp_check 127.0.0.1 "$1" 1; }

# SFTPGo host web port resolver (avoid NGINX :80)
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
EN_APP=false; EN_PG=false; EN_MAILPIT=false; EN_SFTPGO=false; EN_WF2_WORKER=false
EN_LOCAL_HSM=false

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
WF2_WORKER_LEASE="$DEF_WF2_WORKER_LEASE"
WF2_WORKER_BATCH="$DEF_WF2_WORKER_BATCH"
WF2_WORKER_SLEEP="$DEF_WF2_WORKER_SLEEP"

# CLI target flags
ONLY_APP=false; ONLY_DB=false; ONLY_MAIL=false; ONLY_SFTP=false; ONLY_WF2_WORKER=false; ONLY_HSM=false
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

step_workflows2_worker(){
  $EN_APP || return 0
  EN_WF2_WORKER=$(
    ask_yes_no "Delegate workflows2 tasks to a dedicated worker container?" "n" && echo true || echo false
  )
}

step_local_hsm(){
  $EN_APP || return 0
  EN_LOCAL_HSM=$(
    ask_yes_no "Start a separate SoftHSM PKCS#11 proxy server container for local/dev testing? Trustpoint loads the proxy client library; the SoftHSM container keeps the real token store and serves PKCS#11 over the proxy." "y" && echo true || echo false
  )
}

prepare_local_hsm_root(){
  $EN_LOCAL_HSM || return 0
  mkdir -p "$LOCAL_HSM_CONFIG_DIR" "$LOCAL_HSM_LIB_DIR" "$LOCAL_HSM_TOKEN_DIR"

  # Normalize ownership so a non-root SoftHSM container can reuse files
  # created by older root-based runs without requiring host sudo.
  fix_bind_mount_owner "$LOCAL_HSM_ROOT"

  chmod 750 "$LOCAL_HSM_ROOT" "$LOCAL_HSM_CONFIG_DIR" "$LOCAL_HSM_LIB_DIR" 2>/dev/null || true
  chmod 700 "$LOCAL_HSM_TOKEN_DIR" 2>/dev/null || true
}

local_hsm_value(){
  local key="$1"
  [[ -f "$LOCAL_HSM_METADATA_FILE" ]] || return 0
  sed -n "s/^${key}=//p" "$LOCAL_HSM_METADATA_FILE" | head -n1
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
  fi
  echo
  printf "%-22s %s\n" "Mailpit enabled:" "$EN_MAILPIT"
  $EN_MAILPIT && printf "%-22s %s\n" "Mailpit ports:" "SMTP ${MAILPIT_SMTP_PORT}, UI ${MAILPIT_UI_PORT}"
  echo
  printf "%-22s %s\n" "workflows2 worker:" "$EN_WF2_WORKER"
  $EN_WF2_WORKER && {
    printf "%-22s %s\n" "Worker container:" "${WF2_WORKER_NAME}"
  }
  echo
  printf "%-22s %s\n" "SoftHSM service:" "$EN_LOCAL_HSM"
  $EN_LOCAL_HSM && {
    printf "%-22s %s\n" "SoftHSM image:" "Build local -> ${SOFTHSM_IMAGE}"
    printf "%-22s %s\n" "SoftHSM container:" "${SOFTHSM_NAME}"
    printf "%-22s %s\n" "HSM root:" "${LOCAL_HSM_ROOT}"
    printf "%-22s %s\n" "Trustpoint mount:" "${LOCAL_HSM_CONFIG_DIR} -> ${LOCAL_HSM_CONTAINER_CONFIG_DIR} (ro)"
    printf "%-22s %s\n" "Token isolation:" "${LOCAL_HSM_TOKEN_DIR} mounted only into ${SOFTHSM_NAME}"
    printf "%-22s %s\n" "Token label:" "${LOCAL_HSM_TOKEN_LABEL}"
    printf "%-22s %s\n" "Profile name:" "${LOCAL_HSM_PROFILE_NAME}"
  }
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
build_softhsm_image(){ [[ -f "$HSM_DOCKERFILE" ]] || log "Dockerfile not found: $HSM_DOCKERFILE"; log "Building SoftHSM image..."; docker build -f "$HSM_DOCKERFILE" -t "$SOFTHSM_IMAGE" .; }
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

resolve_softhsm_image(){
  $EN_LOCAL_HSM || return 0
  build_softhsm_image
}

configure_selected(){
  if $ONLY_DB; then
    EN_PG=true
    DB_INTERNAL=true
  fi
  $ONLY_MAIL && EN_MAILPIT=true
  $ONLY_SFTP && EN_SFTPGO=true
  $ONLY_HSM && EN_LOCAL_HSM=true

  if $ONLY_APP; then
    EN_APP=true
    configure_app_image_prompt
    EN_WF2_WORKER=$(
      ask_yes_no "Delegate workflows2 tasks to a dedicated worker container?" "n" && echo true || echo false
    )
  elif $ONLY_WF2_WORKER; then
    EN_WF2_WORKER=true
    configure_app_image_prompt
  fi

  # Local/dev safeguard:
  # If the user starts only the app or worker but we already have a local/dev
  # HSM metadata file or a running SoftHSM container, carry the HSM mount/config
  # along automatically so the PKCS#11 provider profile does not become broken.
  if { $ONLY_APP || $ONLY_WF2_WORKER; } && { [[ -f "$LOCAL_HSM_METADATA_FILE" ]] || exists "$SOFTHSM_NAME"; }; then
    EN_LOCAL_HSM=true
  fi

  if $ONLY_APP || $ONLY_WF2_WORKER; then
    if $DB_INTERNAL; then
      APP_DB_HOST="$DEF_DB_HOST_INTERNAL"
      APP_DB_PORT=5432
    else
      APP_DB_HOST="$DB_HOST"
      APP_DB_PORT="$DB_PORT"
    fi
    APP_DB_NAME="$DB_NAME"
    APP_DB_USER="$DB_USER"
    APP_DB_PASS="$DB_PASS"
  fi
}

start_postgres(){
  $DB_INTERNAL || return 0
  ensure_volumes
  local name="postgres"
  stop_one "$name"
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

start_softhsm(){
  $EN_LOCAL_HSM || return 0
  local name="$SOFTHSM_NAME"
  stop_one "$name"
  prepare_local_hsm_root

  log "Starting separate SoftHSM PKCS#11 proxy server container..."
  docker run -d --name "$name" --network "$NET" \
    --user "$(id -u):$(id -g)" \
    -v "${LOCAL_HSM_CONFIG_DIR}:${LOCAL_HSM_CONTAINER_CONFIG_DIR}" \
    -v "${LOCAL_HSM_TOKEN_DIR}:${LOCAL_HSM_CONTAINER_TOKEN_DIR}" \
    -e "TRUSTPOINT_HSM_ROOT=${LOCAL_HSM_CONTAINER_ROOT}" \
    -e "TRUSTPOINT_LOCAL_HSM_TOKEN_LABEL=${LOCAL_HSM_TOKEN_LABEL}" \
    -e "TRUSTPOINT_LOCAL_HSM_PROFILE_NAME=${LOCAL_HSM_PROFILE_NAME}" \
    -e "TRUSTPOINT_LOCAL_HSM_AUTO_BOOTSTRAP=1" \
    "$SOFTHSM_IMAGE" >/dev/null

  sleep 1
  if ! running "$name"; then
    docker logs "$name" >&2 || true
    die "SoftHSM container failed to stay running."
  fi
}

start_app(){
  $EN_APP || return 0
  local name="trustpoint"
  stop_one "$name"
  if port_in_use "$APP_HTTP_HOST"; then die "Host port ${APP_HTTP_HOST} is in use (trustpoint HTTP)."; fi
  if port_in_use "$APP_HTTPS_HOST"; then die "Host port ${APP_HTTPS_HOST} is in use (trustpoint HTTPS)."; fi

  log "Starting trustpoint..."
  local smtp_env=()
  local hsm_env=()

  if ! $EN_LOCAL_HSM && [[ -f "$LOCAL_HSM_METADATA_FILE" ]]; then
    warn "Local/dev HSM metadata exists, but Trustpoint is being started without the HSM config mount."
    warn "Use './tp_wizard.sh up trustpoint hsm' or enable SoftHSM in the full wizard."
  fi

  if $EN_MAILPIT; then
    smtp_env+=( -e "EMAIL_HOST=mailpit" -e "EMAIL_PORT=1025" -e "EMAIL_USE_TLS=0" -e "EMAIL_USE_SSL=0" -e "DEFAULT_FROM_EMAIL=no-reply@trustpoint.local" )
  fi

  if $EN_LOCAL_HSM; then
    prepare_local_hsm_root
    hsm_env+=(
      -e "TRUSTPOINT_HSM_ROOT=${LOCAL_HSM_CONTAINER_ROOT}"
      -e "PKCS11_PROXY_SOCKET=tcp://${SOFTHSM_NAME}:5657"
      -e "TRUSTPOINT_LOCAL_HSM_METADATA_FILE=${LOCAL_HSM_CONTAINER_CONFIG_DIR}/local-dev-token.env"
      -v "${LOCAL_HSM_CONFIG_DIR}:${LOCAL_HSM_CONTAINER_CONFIG_DIR}:ro"
    )
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
    "${hsm_env[@]}" \
    "$APP_IMAGE" >/dev/null
}

start_workflows2_worker(){
  $EN_WF2_WORKER || return 0
  local name="$WF2_WORKER_NAME"
  stop_one "$name"

  log "Starting dedicated workflows2 worker..."

  local env_args=(
    -e "POSTGRES_DB=${APP_DB_NAME}"
    -e "DATABASE_USER=${APP_DB_USER}"
    -e "DATABASE_PASSWORD=${APP_DB_PASS}"
    -e "DATABASE_HOST=${APP_DB_HOST}"
    -e "DATABASE_PORT=${APP_DB_PORT}"
    -e "TRUSTPOINT_SERVICE_ROLE=worker"
    -e "WORKFLOWS2_WORKER_ID=${WF2_WORKER_NAME}"
    -e "WORKFLOWS2_WORKER_LEASE=${WF2_WORKER_LEASE}"
    -e "WORKFLOWS2_WORKER_BATCH=${WF2_WORKER_BATCH}"
    -e "WORKFLOWS2_WORKER_SLEEP=${WF2_WORKER_SLEEP}"
    -e "DEFAULT_FROM_EMAIL=no-reply@trustpoint.local"
  )

  local hsm_mount=()

  if $EN_LOCAL_HSM; then
    prepare_local_hsm_root
    env_args+=(
      -e "TRUSTPOINT_HSM_ROOT=${LOCAL_HSM_CONTAINER_ROOT}"
      -e "PKCS11_PROXY_SOCKET=tcp://${SOFTHSM_NAME}:5657"
    )
    hsm_mount+=( -v "${LOCAL_HSM_CONFIG_DIR}:${LOCAL_HSM_CONTAINER_CONFIG_DIR}:ro" )
  fi

  if $EN_MAILPIT; then
    env_args+=(
      -e "EMAIL_HOST=mailpit"
      -e "EMAIL_PORT=1025"
      -e "EMAIL_USE_TLS=0"
      -e "EMAIL_USE_SSL=0"
    )
  fi

  docker run -d --name "$name" --network "$NET" \
    "${env_args[@]}" \
    "${hsm_mount[@]}" \
    "$APP_IMAGE" >/dev/null
}

provision_local_hsm(){
  $EN_LOCAL_HSM || return 0

  prepare_local_hsm_root

  exists "$SOFTHSM_NAME" || die "SoftHSM container ${SOFTHSM_NAME} does not exist."
  if ! running "$SOFTHSM_NAME"; then
    docker logs "$SOFTHSM_NAME" >&2 || true
    die "SoftHSM container ${SOFTHSM_NAME} is not running."
  fi

  if [[ ! -f "$LOCAL_HSM_METADATA_FILE" ]]; then
    warn "SoftHSM metadata file ${LOCAL_HSM_METADATA_FILE} is not present on the host yet."
  fi

  if exists trustpoint && running trustpoint; then
    log "Trying to configure the active PKCS#11 provider profile in Trustpoint..."
    if ! docker exec trustpoint bash -lc \
      "cd /var/www/html/trustpoint && ./docker/trustpoint/scripts/upsert_local_dev_pkcs11_profile.sh"; then
      warn "SoftHSM is ready, but the local/dev provider profile was not upserted."
      warn "This usually means the Trustpoint crypto tables do not exist yet, or the project database migrations are out of sync."
    fi
  else
    warn "Trustpoint container is not running yet; SoftHSM is ready, but the local/dev provider profile was not upserted."
  fi

  local token_serial module_path
  token_serial="$(local_hsm_value TRUSTPOINT_LOCAL_HSM_TOKEN_SERIAL)"
  module_path="$(local_hsm_value TRUSTPOINT_LOCAL_HSM_MODULE_PATH)"

  if [[ -n "$token_serial" ]]; then
    ok "SoftHSM token '${LOCAL_HSM_TOKEN_LABEL}' is ready (serial ${token_serial})."
  else
    ok "SoftHSM token '${LOCAL_HSM_TOKEN_LABEL}' is ready."
  fi
  [[ -n "$module_path" ]] && ok "PKCS#11 client module path discovered at ${module_path}."
}

# -------------------------- Readiness & Provision -----------------------------
await_softhsm_ready(){
  $EN_LOCAL_HSM || return 0

  if ! exists "$SOFTHSM_NAME"; then
    warn "SoftHSM container ${SOFTHSM_NAME} does not exist."
    return 0
  fi

  echo "Waiting (<= ${READINESS_TIMEOUT}s) for SoftHSM PKCS#11 proxy in container ${SOFTHSM_NAME} ..."
  local until=$(( $(date +%s) + READINESS_TIMEOUT ))
  while (( $(date +%s) < until )); do
    if ! running "$SOFTHSM_NAME"; then
      docker logs "$SOFTHSM_NAME" >&2 || true
      die "SoftHSM container stopped before the proxy became ready."
    fi

    if docker exec "$SOFTHSM_NAME" bash -lc "nc -z 127.0.0.1 5657" >/dev/null 2>&1; then
      ok "SoftHSM PKCS#11 proxy ready in ${SOFTHSM_NAME}"
      return 0
    fi

    printf "."
    sleep 1
  done
  echo
  warn "SoftHSM PKCS#11 proxy not confirmed after ${READINESS_TIMEOUT}s"
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
    printf "."
    sleep 1
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
      printf "."
      sleep 1
    done
    echo
  fi
  await_softhsm_ready
  if $EN_APP; then
    echo "Waiting (<= ${READINESS_TIMEOUT}s) for trustpoint HTTP on localhost:${APP_HTTP_HOST} ..."
    while (( $(date +%s) < deadline )); do
      if tcp_check 127.0.0.1 "$APP_HTTP_HOST" 1; then ok "trustpoint reachable on :$APP_HTTP_HOST"; break; fi
      printf "."
      sleep 1
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
  ok "Virtual folder '${vf_name}' -> '${mapped}' ready."
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

mailpit_has_subject(){
  local subject="$1"
  have curl || return 2
  local until=$(( $(date +%s) + MAILPIT_PROBE_TIMEOUT ))
  local api="http://127.0.0.1:${MAILPIT_UI_PORT}/api/v1/messages"
  while (( $(date +%s) < until )); do
    if curl -fsS "$api" 2>/dev/null | grep -Fq "$subject"; then
      return 0
    fi
    sleep 1
  done
  return 1
}

probe_mailpit_from_container(){
  local container="$1" label="$2"
  exists "$container" || return 0

  local subject="trustpoint wizard ${label} mailpit probe $(date +%s)"
  log "Sending Mailpit probe email from ${label} container..."

  if ! docker exec -e "PROBE_SUBJECT=${subject}" "$container" bash -lc \
    'cd /var/www/html/trustpoint && uv run trustpoint/manage.py shell -c '\''import os; from django.conf import settings; from django.core.mail import send_mail; subject=os.environ["PROBE_SUBJECT"]; send_mail(subject, "Trustpoint Mailpit probe.", getattr(settings, "DEFAULT_FROM_EMAIL", None), ["demo@trustpoint.local"], fail_silently=False)'\''' \
    >/dev/null 2>&1; then
    warn "Mailpit probe failed from ${label} container."
    return 1
  fi

  if ! have curl; then
    warn "curl not found on host; Mailpit probe from ${label} was sent but API verification was skipped."
    return 0
  fi

  if mailpit_has_subject "$subject"; then
    ok "Mailpit received the ${label} probe email."
    return 0
  fi

  warn "Mailpit SMTP accepted the ${label} probe email, but it did not appear in the Mailpit UI within ${MAILPIT_PROBE_TIMEOUT}s."
  return 1
}

verify_mailpit_delivery(){
  $EN_MAILPIT || return 0
  $EN_APP && probe_mailpit_from_container trustpoint "web" || true
  $EN_WF2_WORKER && probe_mailpit_from_container "$WF2_WORKER_NAME" "workflows2-worker" || true
}

show_runtime_status(){
  local net_state="absent" vol_state="absent"
  docker network inspect "$NET" >/dev/null 2>&1 && net_state="present"
  docker volume inspect "$VOL_DB" >/dev/null 2>&1 && vol_state="present"

  echo
  echo "=========================== Runtime Status (Live) ========================"
  printf "%-22s %s\n" "Network:" "${NET} (${net_state})"
  printf "%-22s %s\n" "DB volume:" "${VOL_DB} (${vol_state})"
  echo
  printf "%-20s %-10s %-10s %s\n" "Container" "State" "Health" "Image"
  print_container_status_row trustpoint
  print_container_status_row postgres
  print_container_status_row mailpit
  print_container_status_row "$SOFTHSM_NAME"
  print_container_status_row sftpgo
  print_container_status_row "$WF2_WORKER_NAME"
  echo

  if exists trustpoint; then
    local http_port https_port db_host db_port db_name db_user db_pass
    http_port="$(container_host_port trustpoint 80/tcp)"
    https_port="$(container_host_port trustpoint 443/tcp)"
    db_host="$(container_env trustpoint DATABASE_HOST)"
    db_port="$(container_env trustpoint DATABASE_PORT)"
    db_name="$(container_env trustpoint POSTGRES_DB)"
    db_user="$(container_env trustpoint DATABASE_USER)"
    db_pass="$(container_env trustpoint DATABASE_PASSWORD)"

    [[ -n "$http_port" ]] && printf "%-22s %s\n" "trustpoint HTTP:" "http://localhost:${http_port}"
    [[ -n "$https_port" ]] && printf "%-22s %s\n" "trustpoint HTTPS:" "https://localhost:${https_port}"
    printf "%-22s %s\n" "workflows2 mode:" "managed in Trustpoint settings"
    if [[ -n "$db_host" || -n "$db_port" || -n "$db_name" || -n "$db_user" ]]; then
      printf "%-22s %s\n" "DB connect:" "host=${db_host:-?} port=${db_port:-?} db=${db_name:-?} user=${db_user:-?} pass=$(mask "${db_pass:-}")"
    fi

    if exists "$SOFTHSM_NAME" || [[ -f "$LOCAL_HSM_METADATA_FILE" ]]; then
      printf "%-22s %s\n" "SoftHSM config dir:" "${LOCAL_HSM_CONFIG_DIR}"
      [[ -f "$LOCAL_HSM_METADATA_FILE" ]] && {
        printf "%-22s %s\n" "SoftHSM serial:" "$(local_hsm_value TRUSTPOINT_LOCAL_HSM_TOKEN_SERIAL)"
        printf "%-22s %s\n" "PKCS#11 module:" "$(local_hsm_value TRUSTPOINT_LOCAL_HSM_MODULE_PATH)"
      }
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

  if exists "$SOFTHSM_NAME"; then
    printf "%-22s %s\n" "SoftHSM service:" "${SOFTHSM_NAME} (network-only :5657)"
    printf "%-22s %s\n" "Trustpoint mount:" "${LOCAL_HSM_CONFIG_DIR} (ro, config only)"
    printf "%-22s %s\n" "SoftHSM token dir:" "${LOCAL_HSM_TOKEN_DIR}"
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

  echo "========================================================================="
}

# -------------------------- Summary ------------------------------------------
final_summary(){
  echo
  echo "========================= Runtime Summary (Actual) ======================="
  printf "%-22s %s\n" "Network:" "$NET"
  printf "%-22s %s\n" "Containers:" "$(docker ps --format '{{.Names}}' | grep -E '^(trustpoint|postgres|mailpit|softhsm|sftpgo|trustpoint-worker)$' || true)"
  echo
  if $EN_APP; then
    printf "%-22s %s\n" "trustpoint:" "http://localhost:80  |  https://localhost:443"
    printf "%-22s %s\n" "workflows2 mode:" "managed in Trustpoint settings (default: auto)"
  fi
  if $DB_INTERNAL; then
    printf "%-22s %s\n" "PostgreSQL:" "tcp://localhost:${DB_PORT}  (container port 5432)"
  fi
  if $EN_APP; then
    printf "%-22s %s\n" "DB connect:" "host=${APP_DB_HOST} port=${APP_DB_PORT} db=${APP_DB_NAME} user=${APP_DB_USER} pass=$(mask "$APP_DB_PASS")"
  fi
  $EN_MAILPIT && printf "%-22s %s\n" "Mailpit UI:" "http://localhost:${MAILPIT_UI_PORT}  (SMTP :${MAILPIT_SMTP_PORT})"

  if exists "$SOFTHSM_NAME" || [[ -f "$LOCAL_HSM_METADATA_FILE" ]]; then
    printf "%-22s %s\n" "SoftHSM service:" "${SOFTHSM_NAME} (proxy at tcp://${SOFTHSM_NAME}:5657)"
    printf "%-22s %s\n" "SoftHSM state:" "${LOCAL_HSM_ROOT}"
    printf "%-22s %s\n" "Trustpoint mount:" "${LOCAL_HSM_CONFIG_DIR} -> ${LOCAL_HSM_CONTAINER_CONFIG_DIR} (ro)"
    printf "%-22s %s\n" "Token isolation:" "${LOCAL_HSM_TOKEN_DIR} stays outside the Trustpoint container"
    printf "%-22s %s\n" "Token label:" "${LOCAL_HSM_TOKEN_LABEL}"
    [[ -f "$LOCAL_HSM_METADATA_FILE" ]] && {
      printf "%-22s %s\n" "Token serial:" "$(local_hsm_value TRUSTPOINT_LOCAL_HSM_TOKEN_SERIAL)"
      printf "%-22s %s\n" "Profile name:" "$(local_hsm_value TRUSTPOINT_LOCAL_HSM_PROFILE_NAME)"
      printf "%-22s %s\n" "PKCS#11 module:" "$(local_hsm_value TRUSTPOINT_LOCAL_HSM_MODULE_PATH)"
    }
  fi

  if $EN_WF2_WORKER; then
    printf "%-22s %s\n" "workflows2 worker:" "${WF2_WORKER_NAME}"
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
  step_workflows2_worker
  step_local_hsm
  show_plan
  ask_yes_no "Proceed with these settings?" "y" || { warn "Aborted by user."; exit 1; }
  resolve_app_image
  resolve_softhsm_image
  $DB_INTERNAL && ensure_volumes
  start_postgres
  start_mailpit
  start_softhsm
  start_sftpgo
  $EN_WF2_WORKER || stop_one "$WF2_WORKER_NAME"
  start_app
  start_workflows2_worker
  $NOWAIT || await_readiness
  $NOWAIT || provision_local_hsm
  $NOWAIT || provision_sftpgo_backup_user
  $NOWAIT || verify_mailpit_delivery
  $NOWAIT || wait_tls_fingerprint || true
  final_summary
}

# -------------------------- Service selection & CLI --------------------------
usage(){
  cat <<'EOF2'
Commands:
  (no command)       Run interactive wizard
  up [demo|trustpoint|db|mail|hsm|sftp|worker] [--nowait]
  down [demo|trustpoint|db|mail|hsm|sftp|worker]
  logs [trustpoint|db|mail|hsm|sftp|worker]
  status
  nuke
  help

Also supported (legacy): --only trustpoint|db|mail|hsm|sftp|worker|demo
EOF2
}

map_only_to_flags(){
  case "$1" in
    demo)  ONLY_APP=true; ONLY_DB=true; ONLY_MAIL=true; ONLY_HSM=true; ONLY_SFTP=true ;;
    trustpoint|app)  ONLY_APP=true ;;
    db)   ONLY_DB=true ;;
    mail) ONLY_MAIL=true ;;
    hsm|softhsm) ONLY_HSM=true ;;
    sftp) ONLY_SFTP=true ;;
    worker) ONLY_WF2_WORKER=true ;;
    *) die "Unknown target: $1 (use trustpoint|db|mail|hsm|sftp|worker|demo)" ;;
  esac
}

set_targets_from_args(){
  local any=false
  while [[ $# -gt 0 ]]; do
    case "$1" in
      demo|trustpoint|app|db|mail|hsm|softhsm|sftp|worker) map_only_to_flags "$1"; any=true; shift ;;
      --only) map_only_to_flags "${2:-}"; any=true; shift 2 ;;
      --nowait) NOWAIT=true; shift ;;
      *) die "Unknown option/target: $1" ;;
    esac
  done

  # Default local/dev bring-up:
  # start Trustpoint, PostgreSQL, and the local SoftHSM service together.
  if ! $any; then
    ONLY_APP=true
    ONLY_DB=true
    ONLY_HSM=true
  fi
}

start_selected(){
  configure_selected
  ensure_network
  resolve_app_image
  resolve_softhsm_image
  $ONLY_DB   && { EN_PG=true; ensure_volumes; start_postgres; }
  $ONLY_MAIL && { EN_MAILPIT=true; start_mailpit; }
  $ONLY_HSM  && start_softhsm
  $ONLY_SFTP && { EN_SFTPGO=true; start_sftpgo; }
  $EN_WF2_WORKER || { $ONLY_APP && stop_one "$WF2_WORKER_NAME"; }
  $ONLY_APP  && start_app
  $EN_WF2_WORKER && start_workflows2_worker

  $NOWAIT || await_readiness
  $NOWAIT || provision_local_hsm
  $NOWAIT || provision_sftpgo_backup_user
  $NOWAIT || verify_mailpit_delivery
  $NOWAIT || wait_tls_fingerprint || true
  final_summary
}

down_selected(){
  local done=false
  $ONLY_APP && { stop_one trustpoint; stop_one "$WF2_WORKER_NAME"; done=true; }
  $ONLY_DB && stop_one postgres && done=true
  $ONLY_MAIL && stop_one mailpit && done=true
  $ONLY_HSM && stop_one "$SOFTHSM_NAME" && done=true
  $ONLY_SFTP && stop_one sftpgo && done=true
  $ONLY_WF2_WORKER && stop_one "$WF2_WORKER_NAME" && done=true
  $done || { stop_one trustpoint; stop_one postgres; stop_one mailpit; stop_one "$SOFTHSM_NAME"; stop_one sftpgo; stop_one "$WF2_WORKER_NAME"; }
  ok "Stopped."
}

logs_selected(){
  local target="trustpoint"
  $ONLY_DB && target="postgres"
  $ONLY_MAIL && target="mailpit"
  $ONLY_HSM && target="$SOFTHSM_NAME"
  $ONLY_SFTP && target="sftpgo"
  $ONLY_WF2_WORKER && target="$WF2_WORKER_NAME"
  exists "$target" || die "Container not found: $target"
  docker logs -f "$target"
}

nuke_cmd(){
  read -r -p "Remove ALL project containers, network, DB volume, ./var/hsm, and ./sftpgo-data? [y/N] " a; [[ "${a}" == "y" ]] || exit 0
  read -r -p "Are you sure? This is destructive. [y/N] " b; [[ "${b}" == "y" ]] || exit 0

  mapfile -t project_volumes < <(collect_project_volumes)

  stop_one trustpoint
  stop_one postgres
  stop_one mailpit
  stop_one "$SOFTHSM_NAME"
  stop_one sftpgo
  stop_one "$WF2_WORKER_NAME"

  docker network rm "$NET" >/dev/null 2>&1 || true

  for v in "${project_volumes[@]}"; do
    [[ -n "$v" ]] || continue
    docker volume rm "$v" >/dev/null 2>&1 || true
  done

  if [[ -d "$LOCAL_HSM_ROOT" ]]; then
    purge_bind_mount_dir "$LOCAL_HSM_ROOT"
    rm -rf "$LOCAL_HSM_ROOT" 2>/dev/null || true
  fi

  if [[ -d "$SFTPGO_ROOT" ]]; then
    purge_bind_mount_dir "$SFTPGO_ROOT"
    rm -rf "$SFTPGO_ROOT" 2>/dev/null || true
  fi

  ok "Project resources removed."
}

# -------------------------- Arg parsing & dispatch ----------------------------
cmd="${1:-}"
preflight
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
  status)
    shift || true
    [[ $# -eq 0 ]] || die "status does not take targets. Use it without arguments."
    show_runtime_status
    ;;
  nuke) nuke_cmd ;;
  *) usage; die "Unknown command: $cmd" ;;
esac
