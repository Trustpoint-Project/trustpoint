#!/usr/bin/env bash

local_hsm_value() {
  local key="$1"
  [[ -r "$LOCAL_HSM_METADATA_FILE" ]] || return 0
  sed -n "s/^${key}=//p" "$LOCAL_HSM_METADATA_FILE" | head -n1
}

local_hsm_user_pin() {
  local pin_file="$LOCAL_HSM_CONFIG_DIR/user-pin.txt"
  if [[ -r "$pin_file" ]]; then
    tr -d '\r\n' <"$pin_file"
  elif container_exists "$SOFTHSM_NAME"; then
    docker exec "$SOFTHSM_NAME" sh -c \
      "tr -d '\\r\\n' < '$LOCAL_HSM_CONTAINER_CONFIG_DIR/user-pin.txt'" 2>/dev/null || true
  fi
}

prepare_local_hsm_root() {
  mkdir -p "$LOCAL_HSM_CONFIG_DIR" "$LOCAL_HSM_TOKEN_DIR"
  docker run --rm --user 0:0 --entrypoint sh -v "$LOCAL_HSM_ROOT:/target" "$SOFTHSM_IMAGE" -c '
    set -e
    mkdir -p /target/config /target/tokens
    chown -R 33:33 /target
    chmod 0755 /target /target/config
    chmod 0700 /target/tokens
    find /target/config -maxdepth 1 -type f -name "*.env" -exec chmod 0644 {} +
    find /target/config -maxdepth 1 -type f -name "*pin*.txt" -exec chmod 0600 {} +
  '
}

wait_softhsm_ready() {
  local timeout=60
  for ((i=0; i<timeout; i++)); do
    if container_running "$SOFTHSM_NAME" \
      && [[ -s "$LOCAL_HSM_METADATA_FILE" ]] \
      && docker exec "$SOFTHSM_NAME" nc -z 127.0.0.1 5657 >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  docker logs "$SOFTHSM_NAME" >&2 2>/dev/null || true
  die 'SoftHSM did not initialize within 60 seconds.'
}

start_softhsm() {
  remove_container "$SOFTHSM_NAME"
  log 'Building SoftHSM image...'
  docker build --quiet -f "$ROOT_DIR/docker/softhsm/Dockerfile" -t "$SOFTHSM_IMAGE" "$ROOT_DIR"
  prepare_local_hsm_root
  start_container "$SOFTHSM_NAME" \
    -v "$LOCAL_HSM_CONFIG_DIR:$LOCAL_HSM_CONTAINER_CONFIG_DIR" \
    -v "$LOCAL_HSM_TOKEN_DIR:$LOCAL_HSM_CONTAINER_TOKEN_DIR" \
    -e TRUSTPOINT_HSM_ROOT="$LOCAL_HSM_CONTAINER_ROOT" \
    -e TRUSTPOINT_LOCAL_HSM_TOKEN_LABEL="$LOCAL_HSM_TOKEN_LABEL" \
    -e TRUSTPOINT_LOCAL_HSM_PROFILE_NAME="$LOCAL_HSM_PROFILE_NAME" \
    -e TRUSTPOINT_LOCAL_HSM_MODULE_PATH="$LOCAL_HSM_CONTAINER_MODULE_PATH" \
    -e TRUSTPOINT_LOCAL_HSM_SOFTHSM2_CONF="$LOCAL_HSM_CONTAINER_SOFTHSM2_CONF" \
    -e TRUSTPOINT_LOCAL_HSM_AUTO_BOOTSTRAP=1 \
    "$SOFTHSM_IMAGE"
  wait_softhsm_ready
  ok 'SoftHSM started'
}
