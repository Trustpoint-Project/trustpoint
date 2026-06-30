step_local_hsm(){
  $EN_APP || return 0
  EN_LOCAL_HSM=$(
    ask_yes_no "Start a separate SoftHSM PKCS#11 proxy server container? (Demo only)" "y" && echo true || echo false
  )
}

prepare_local_hsm_bind_mount(){
  local uid="$1" gid="$2"
  mkdir -p "$LOCAL_HSM_CONFIG_DIR" "$LOCAL_HSM_LIB_DIR" "$LOCAL_HSM_TOKEN_DIR"

  docker run --rm \
    -v "${LOCAL_HSM_ROOT}:/target" \
    debian:trixie-slim \
    bash -lc "
      set -e
      mkdir -p /target/config /target/lib /target/tokens
      chown -R ${uid}:${gid} /target
      chmod 0755 /target /target/config /target/lib
      chmod 0700 /target/tokens
      find /target/config -maxdepth 1 -type f -name '*.env' -exec chmod 0644 {} +
      find /target/config -maxdepth 1 -type f \\( -name '*pin*.txt' -o -name '*PIN*.txt' \\) -exec chmod 0600 {} +
      find /target/config -maxdepth 1 -type f ! -name '*.env' ! -name '*pin*.txt' ! -name '*PIN*.txt' -exec chmod 0640 {} +
    "
}

prepare_local_hsm_root(){
  $EN_LOCAL_HSM || return 0
  prepare_local_hsm_bind_mount "$LOCAL_HSM_RUNTIME_UID" "$LOCAL_HSM_RUNTIME_GID"
}

local_hsm_value(){
  local key="$1"
  [[ -f "$LOCAL_HSM_METADATA_FILE" ]] || return 0
  sed -n "s/^${key}=//p" "$LOCAL_HSM_METADATA_FILE" | head -n1
}

local_hsm_user_pin(){
  local pin_file="${LOCAL_HSM_CONFIG_DIR}/user-pin.txt"

  if [[ -r "$pin_file" ]]; then
    tr -d '\r\n' < "$pin_file"
    return 0
  fi

  if exists "$SOFTHSM_NAME"; then
    docker exec "$SOFTHSM_NAME" sh -c \
      "tr -d '\\r\\n' < '${LOCAL_HSM_CONTAINER_CONFIG_DIR}/user-pin.txt'" 2>/dev/null || true
  fi
}

build_softhsm_image(){
  [[ -f "$HSM_DOCKERFILE" ]] || die "Dockerfile not found: $HSM_DOCKERFILE"
  log "Building SoftHSM image..."
  docker build -f "$HSM_DOCKERFILE" -t "$SOFTHSM_IMAGE" .
}

resolve_softhsm_image(){
  $EN_LOCAL_HSM || return 0
  build_softhsm_image
}

start_softhsm(){
  $EN_LOCAL_HSM || return 0

  local name="$SOFTHSM_NAME"
  stop_one "$name"
  prepare_local_hsm_root

  log "Starting separate SoftHSM PKCS#11 proxy server container..."
  docker run -d --name "$name" --network "$NET" \
    --user "${LOCAL_HSM_RUNTIME_UID}:${LOCAL_HSM_RUNTIME_GID}" \
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

await_softhsm_ready(){
  $EN_LOCAL_HSM || return 0

  if ! exists "$SOFTHSM_NAME"; then
    warn "SoftHSM container ${SOFTHSM_NAME} does not exist."
    return 0
  fi

  echo "Waiting (<= ${READINESS_TIMEOUT}s) for SoftHSM PKCS#11 proxy in container ${SOFTHSM_NAME} ..."
  local deadline=$(( $(date +%s) + READINESS_TIMEOUT ))

  while (( $(date +%s) < deadline )); do
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

provision_local_hsm(){
  $EN_LOCAL_HSM || return 0

  prepare_local_hsm_root

  if ! exists "$SOFTHSM_NAME"; then
    warn "SoftHSM container ${SOFTHSM_NAME} does not exist."
    return 0
  fi

  if ! running "$SOFTHSM_NAME"; then
    docker logs "$SOFTHSM_NAME" >&2 || true
    warn "SoftHSM container ${SOFTHSM_NAME} is not running."
    return 0
  fi

  if [[ ! -f "$LOCAL_HSM_METADATA_FILE" ]]; then
    warn "SoftHSM metadata file ${LOCAL_HSM_METADATA_FILE} is not present on the host yet."
  fi

  if exists trustpoint && running trustpoint; then
    log "Trying to configure the active PKCS#11 provider profile in Trustpoint..."
    if ! docker exec trustpoint bash -lc \
      "cd /var/www/html/trustpoint && ./docker/trustpoint/scripts/upsert_local_dev_pkcs11_profile.sh"; then
      warn "SoftHSM is ready, but the local/dev provider profile was not upserted."
      warn "This usually means the Trustpoint crypto tables do not exist yet, or migrations are not ready."
    fi
  fi

  local token_serial
  token_serial="$(local_hsm_value TRUSTPOINT_LOCAL_HSM_TOKEN_SERIAL)"
  if [[ -n "$token_serial" ]]; then
    ok "SoftHSM token '${LOCAL_HSM_TOKEN_LABEL}' is ready (serial ${token_serial})."
  else
    ok "SoftHSM token '${LOCAL_HSM_TOKEN_LABEL}' is ready."
  fi
}

local_hsm_env_args(){
  $EN_LOCAL_HSM || return 0
  printf '%s\0' \
    -e "TRUSTPOINT_HSM_ROOT=${LOCAL_HSM_CONTAINER_ROOT}" \
    -e "PKCS11_PROXY_SOCKET=tcp://${SOFTHSM_NAME}:5657" \
    -e "TRUSTPOINT_LOCAL_HSM_ENABLED=1" \
    -e "TRUSTPOINT_LOCAL_HSM_TOKEN_LABEL=${LOCAL_HSM_TOKEN_LABEL}" \
    -e "TRUSTPOINT_LOCAL_HSM_PROFILE_NAME=${LOCAL_HSM_PROFILE_NAME}" \
    -e "TRUSTPOINT_LOCAL_HSM_TOKEN_SERIAL=$(local_hsm_value TRUSTPOINT_LOCAL_HSM_TOKEN_SERIAL)" \
    -e "TRUSTPOINT_LOCAL_HSM_MODULE_PATH=/usr/lib/libpkcs11-proxy.so" \
    -e "TRUSTPOINT_LOCAL_HSM_USER_PIN_FILE=${LOCAL_HSM_CONTAINER_ROOT}/config/user-pin.txt"
}

local_hsm_mount_args(){
  $EN_LOCAL_HSM || return 0
  prepare_local_hsm_root
  printf '%s\0' \
    -v "${LOCAL_HSM_CONFIG_DIR}:${LOCAL_HSM_CONTAINER_CONFIG_DIR}" \
    -v "${LOCAL_HSM_LIB_DIR}:${LOCAL_HSM_CONTAINER_ROOT}/lib"
}
