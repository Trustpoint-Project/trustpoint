#!/usr/bin/env bash

build_trustpoint() {
  $BUILD_LOCAL || return 0
  log 'Building Trustpoint image...'
  docker build --quiet -f "$TP_DOCKERFILE" -t "$APP_IMAGE" "$ROOT_DIR"
}

start_trustpoint() {
  build_trustpoint
  remove_compose_service trustpoint
  remove_container trustpoint
  local soft_hsm_args=()
  if state_has softhsm; then
    soft_hsm_args+=(
      -v "$LOCAL_HSM_CONFIG_DIR:$LOCAL_HSM_CONTAINER_CONFIG_DIR"
      -v "$LOCAL_HSM_TOKEN_DIR:$LOCAL_HSM_CONTAINER_TOKEN_DIR"
      -e TRUSTPOINT_HSM_ROOT="$LOCAL_HSM_CONTAINER_ROOT"
      -e SOFTHSM2_CONF="$LOCAL_HSM_CONTAINER_SOFTHSM2_CONF"
      -e TRUSTPOINT_LOCAL_HSM_ENABLED=1
      -e TRUSTPOINT_LOCAL_HSM_TOKEN_LABEL="$LOCAL_HSM_TOKEN_LABEL"
      -e TRUSTPOINT_LOCAL_HSM_TOKEN_SERIAL="$(local_hsm_value TRUSTPOINT_LOCAL_HSM_TOKEN_SERIAL)"
      -e TRUSTPOINT_LOCAL_HSM_PROFILE_NAME="$LOCAL_HSM_PROFILE_NAME"
      -e TRUSTPOINT_LOCAL_HSM_MODULE_PATH="$LOCAL_HSM_CONTAINER_MODULE_PATH"
      -e TRUSTPOINT_LOCAL_HSM_USER_PIN_FILE="$LOCAL_HSM_CONTAINER_CONFIG_DIR/user-pin.txt"
      -e TRUSTPOINT_LOCAL_HSM_CONFIG_ENV_VAR=SOFTHSM2_CONF
      -e TRUSTPOINT_LOCAL_HSM_SOFTHSM2_CONF="$LOCAL_HSM_CONTAINER_SOFTHSM2_CONF"
    )
  fi
  local usb_hsm_args=()
  local host_usb_bus="${TP_USB_BUS_PATH:-/dev/bus/usb}"
  if $ENABLE_USB_PASSTHROUGH; then
    [[ -d "$host_usb_bus" ]] || die \
      "USB HSM passthrough requested, but the host USB bus is unavailable at ${host_usb_bus}."
    usb_hsm_args+=(
      --mount "type=bind,source=${host_usb_bus},target=/dev/bus/usb"
      --device-cgroup-rule 'c 189:* rwm'
    )
  fi
  local mail_args=()
  if state_has mail; then
    mail_args+=(
      -e EMAIL_HOST=mailpit
      -e EMAIL_PORT=1025
      -e EMAIL_USE_TLS=0
      -e EMAIL_USE_SSL=0
      -e DEFAULT_FROM_EMAIL=no-reply@trustpoint.local
    )
  fi
  start_container trustpoint --network-alias trustpoint.local --add-host host.docker.internal:host-gateway \
    "${soft_hsm_args[@]}" \
    "${usb_hsm_args[@]}" \
    -p "${TP_HTTP_PORT}:80" -p "${TP_HTTPS_PORT}:443" \
    -e TRUSTPOINT_PHASE=auto -e POSTGRES_DB="$DB_NAME" -e DATABASE_USER="$DB_USER" \
    -e DATABASE_PASSWORD="$DB_PASS" -e DATABASE_HOST="$APP_DB_HOST" -e DATABASE_PORT="$APP_DB_PORT" \
    -e TP_ADMIN_USERNAME="$TP_ADMIN_USERNAME" -e TP_ADMIN_PASSWORD="$TP_ADMIN_PASSWORD" \
    -e TP_ADMIN_EMAIL="$TP_ADMIN_EMAIL" -e TP_AUTO_SETUP="$TP_AUTO_SETUP" \
    -e TP_INJECT_DEMO_DATA="$TP_INJECT_DEMO_DATA" -e TP_TLS_DNS_NAMES="$TP_TLS_DNS_NAMES" \
    -e TP_HTTP_PORT="$TP_HTTP_PORT" -e TP_HTTPS_PORT="$TP_HTTPS_PORT" \
    -e TP_USB_HSM_PASSTHROUGH="$ENABLE_USB_PASSTHROUGH" \
    -e TP_ENABLE_PROMETHEUS_METRICS="$ENABLE_METRICS" \
    -e TP_TLS_IPV4_ADDRESSES="$TP_TLS_IPV4_ADDRESSES" -e TP_TLS_IPV6_ADDRESSES="$TP_TLS_IPV6_ADDRESSES" \
    "${mail_args[@]}" \
    "$APP_IMAGE"
  ok 'Trustpoint started'
}
