#!/usr/bin/env bash
set -euo pipefail

log() {
  printf '[softhsm-entrypoint] %s\n' "$*"
}

die() {
  log "$*"
  exit 1
}

HSM_ROOT="${TRUSTPOINT_HSM_ROOT:-/var/lib/trustpoint/hsm}"
HSM_CONFIG_DIR="${TRUSTPOINT_HSM_CONFIG_DIR:-${HSM_ROOT}/config}"
HSM_TOKEN_DIR="${TRUSTPOINT_HSM_TOKEN_DIR:-${HSM_ROOT}/tokens}"
SOFTHSM2_CONF="${SOFTHSM2_CONF:-${HSM_CONFIG_DIR}/softhsm2.conf}"
SOCKET_DIR="/tmp/pkcs11-socket"
SOCKET_PATH="${SOCKET_DIR}/socket.pkcs11"

resolve_softhsm_module() {
  local candidate=""

  if [[ -n "${TRUSTPOINT_SOFTHSM_MODULE_PATH:-}" ]]; then
    printf '%s\n' "${TRUSTPOINT_SOFTHSM_MODULE_PATH}"
    return 0
  fi

  candidate="$(ldconfig -p 2>/dev/null | awk '/libsofthsm2\.so/ {print $NF; exit}')"
  if [[ -n "${candidate}" ]]; then
    printf '%s\n' "${candidate}"
    return 0
  fi

  for candidate in \
    /usr/lib/softhsm/libsofthsm2.so \
    /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so \
    /usr/lib/aarch64-linux-gnu/softhsm/libsofthsm2.so
  do
    if [[ -f "${candidate}" ]]; then
      printf '%s\n' "${candidate}"
      return 0
    fi
  done

  return 1
}

safe_chmod() {
  local mode="$1"
  local path="$2"
  [[ -e "${path}" ]] || return 0
  if [[ -w "${path}" || -O "${path}" ]]; then
    chmod "${mode}" "${path}" 2>/dev/null || true
  fi
}

SOFTHSM_MODULE_PATH="$(resolve_softhsm_module)" || die "Could not locate libsofthsm2.so"
[[ -f "${SOFTHSM_MODULE_PATH}" ]] || die "Resolved SoftHSM module path does not exist: ${SOFTHSM_MODULE_PATH}"

mkdir -p "${HSM_CONFIG_DIR}" "${HSM_TOKEN_DIR}" "${SOCKET_DIR}"

safe_chmod 0750 "${HSM_CONFIG_DIR}"
safe_chmod 0700 "${HSM_TOKEN_DIR}"
safe_chmod 0755 "${SOCKET_DIR}"

if [[ ! -f "${SOFTHSM2_CONF}" ]] || ! grep -Fq "directories.tokendir = ${HSM_TOKEN_DIR}" "${SOFTHSM2_CONF}"; then
  cp /opt/trustpoint-softhsm/softhsm.conf "${SOFTHSM2_CONF}"
  safe_chmod 0640 "${SOFTHSM2_CONF}"
fi

export SOFTHSM2_CONF

log "Using SoftHSM module: ${SOFTHSM_MODULE_PATH}"
log "Using SoftHSM config: ${SOFTHSM2_CONF}"
log "Using token dir: ${HSM_TOKEN_DIR}"

# Bootstrap before starting the proxy daemon so the daemon sees the initialized
# token immediately instead of keeping a stale uninitialized slot view.
if [[ "${TRUSTPOINT_LOCAL_HSM_AUTO_BOOTSTRAP:-1}" == "1" ]]; then
  log "Bootstrapping local/dev SoftHSM token before starting pkcs11-daemon..."
  if ! /opt/trustpoint-softhsm/scripts/bootstrap_local_dev_token.sh; then
    log "SoftHSM bootstrap failed."
    log "Check ownership and permissions under ${HSM_CONFIG_DIR} and ${HSM_TOKEN_DIR}."
    exit 1
  fi
fi

cleanup() {
  kill "${DAEMON_PID:-}" "${SOCAT_PID:-}" 2>/dev/null || true
}

trap cleanup EXIT INT TERM

pkcs11-daemon "${SOFTHSM_MODULE_PATH}" "${SOCKET_DIR}" &
DAEMON_PID=$!

for _ in $(seq 1 20); do
  if [[ -S "${SOCKET_PATH}" ]]; then
    break
  fi
  if ! kill -0 "${DAEMON_PID}" 2>/dev/null; then
    wait "${DAEMON_PID}" || true
    die "pkcs11-daemon exited before creating ${SOCKET_PATH}"
  fi
  sleep 0.2
done

[[ -S "${SOCKET_PATH}" ]] || die "pkcs11-daemon did not create ${SOCKET_PATH}"

socat TCP-LISTEN:5657,fork,reuseaddr UNIX-CONNECT:"${SOCKET_PATH}" &
SOCAT_PID=$!

wait -n "${DAEMON_PID}" "${SOCAT_PID}"
status=$?
exit "${status}"
