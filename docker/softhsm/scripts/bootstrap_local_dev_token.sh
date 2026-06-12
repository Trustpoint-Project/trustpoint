#!/usr/bin/env bash
set -euo pipefail

HSM_ROOT="${TRUSTPOINT_HSM_ROOT:-/var/lib/trustpoint/hsm}"
HSM_CONFIG_DIR="${TRUSTPOINT_HSM_CONFIG_DIR:-${HSM_ROOT}/config}"
HSM_TOKEN_DIR="${TRUSTPOINT_HSM_TOKEN_DIR:-${HSM_ROOT}/tokens}"
SOFTHSM2_CONF="${SOFTHSM2_CONF:-${HSM_CONFIG_DIR}/softhsm2.conf}"

TOKEN_LABEL="${TRUSTPOINT_LOCAL_HSM_TOKEN_LABEL:-Trustpoint-SoftHSM}"
PROFILE_NAME="${TRUSTPOINT_LOCAL_HSM_PROFILE_NAME:-local-dev-softhsm}"
USER_PIN_FILE="${TRUSTPOINT_LOCAL_HSM_USER_PIN_FILE:-${HSM_CONFIG_DIR}/user-pin.txt}"
SO_PIN_FILE="${TRUSTPOINT_LOCAL_HSM_SO_PIN_FILE:-${HSM_CONFIG_DIR}/so-pin.txt}"
METADATA_FILE="${TRUSTPOINT_LOCAL_HSM_METADATA_FILE:-${HSM_CONFIG_DIR}/local-dev-token.env}"
PROXY_MODULE_PATH="${TRUSTPOINT_LOCAL_HSM_PROXY_MODULE_PATH:-/usr/lib/libpkcs11-proxy.so}"
PROXY_SOCKET="${PKCS11_PROXY_SOCKET:-tcp://softhsm:5657}"
TRUSTPOINT_USER_PIN_FILE="${TRUSTPOINT_LOCAL_HSM_TRUSTPOINT_USER_PIN_FILE:-/var/lib/trustpoint/hsm/config/user-pin.txt}"

log() {
  printf '[softhsm-bootstrap] %s\n' "$*"
}

safe_chmod() {
  local mode="$1"
  local path="$2"
  [[ -e "${path}" ]] || return 0
  if [[ -w "${path}" || -O "${path}" ]]; then
    chmod "${mode}" "${path}" 2>/dev/null || true
  fi
}

random_secret() {
  # Generate exactly 24 alphanumeric-ish characters without using a pipeline
  # that can trip pipefail via SIGPIPE.
  od -An -N12 -tx1 /dev/urandom | tr -d ' \n'
}

ensure_dirs() {
  mkdir -p "${HSM_CONFIG_DIR}" "${HSM_TOKEN_DIR}"
  safe_chmod 0750 "${HSM_CONFIG_DIR}"
  safe_chmod 0700 "${HSM_TOKEN_DIR}"
}

ensure_pin_file() {
  local pin_file="$1"
  if [[ ! -s "${pin_file}" ]]; then
    log "Creating PIN file ${pin_file}"
    umask 077
    random_secret >"${pin_file}"
  fi
  safe_chmod 0600 "${pin_file}"
}

ensure_config() {
  if [[ ! -f "${SOFTHSM2_CONF}" ]] || ! grep -Fq "directories.tokendir = ${HSM_TOKEN_DIR}" "${SOFTHSM2_CONF}"; then
    log "Writing SoftHSM config to ${SOFTHSM2_CONF}"
    cp /opt/trustpoint-softhsm/softhsm.conf "${SOFTHSM2_CONF}"
    safe_chmod 0640 "${SOFTHSM2_CONF}"
  fi
}

token_serial_for_label() {
  SOFTHSM2_CONF="${SOFTHSM2_CONF}" softhsm2-util --show-slots | awk -v want="${TOKEN_LABEL}" '
    /^[[:space:]]*Slot[[:space:]]/ {
      serial = ""
      next
    }
    /^[[:space:]]*Serial number:/ {
      line = $0
      sub(/^[[:space:]]*Serial number:[[:space:]]*/, "", line)
      gsub(/[[:space:]]+$/, "", line)
      serial = line
      next
    }
    /^[[:space:]]*Label:/ {
      line = $0
      sub(/^[[:space:]]*Label:[[:space:]]*/, "", line)
      gsub(/[[:space:]]+$/, "", line)
      if (line == want && serial != "") {
        print serial
        exit
      }
    }
  '
}

write_metadata() {
  local token_serial="$1"
  cat >"${METADATA_FILE}" <<EOF
TRUSTPOINT_LOCAL_HSM_TOKEN_LABEL=${TOKEN_LABEL}
TRUSTPOINT_LOCAL_HSM_TOKEN_SERIAL=${token_serial}
TRUSTPOINT_LOCAL_HSM_MODULE_PATH=${PROXY_MODULE_PATH}
TRUSTPOINT_LOCAL_HSM_PROFILE_NAME=${PROFILE_NAME}
TRUSTPOINT_LOCAL_HSM_USER_PIN_FILE=${TRUSTPOINT_USER_PIN_FILE}
TRUSTPOINT_LOCAL_HSM_PROXY_SOCKET=${PROXY_SOCKET}
EOF
  safe_chmod 0600 "${METADATA_FILE}"
}

main() {
  local token_serial user_pin so_pin

  ensure_dirs
  ensure_pin_file "${USER_PIN_FILE}"
  ensure_pin_file "${SO_PIN_FILE}"
  ensure_config

  token_serial="$(token_serial_for_label)"
  if [[ -z "${token_serial}" ]]; then
    log "Initializing SoftHSM token '${TOKEN_LABEL}'"
    user_pin="$(<"${USER_PIN_FILE}")"
    so_pin="$(<"${SO_PIN_FILE}")"
    SOFTHSM2_CONF="${SOFTHSM2_CONF}" softhsm2-util --init-token --free \
      --label "${TOKEN_LABEL}" \
      --pin "${user_pin}" \
      --so-pin "${so_pin}" >/dev/null
    token_serial="$(token_serial_for_label)"
  fi

  if [[ -z "${token_serial}" ]]; then
    log "Unable to resolve token serial for '${TOKEN_LABEL}'."
    exit 1
  fi

  write_metadata "${token_serial}"
  log "SoftHSM token '${TOKEN_LABEL}' is ready with serial '${token_serial}'."
}

main "$@"
