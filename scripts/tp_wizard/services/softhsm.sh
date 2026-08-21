#!/usr/bin/env bash

start_softhsm() {
  mkdir -p "$LOCAL_HSM_ROOT/config" "$LOCAL_HSM_ROOT/tokens"
  remove_container "$SOFTHSM_NAME"
  docker build -f "$ROOT_DIR/docker/softhsm/Dockerfile" -t "$SOFTHSM_IMAGE" "$ROOT_DIR"
  start_container "$SOFTHSM_NAME" -v "$LOCAL_HSM_ROOT/config:/var/lib/trustpoint/hsm/config" \
    -v "$LOCAL_HSM_ROOT/tokens:/var/lib/trustpoint/hsm/tokens" -e TRUSTPOINT_HSM_ROOT=/var/lib/trustpoint/hsm "$SOFTHSM_IMAGE"
  ok 'SoftHSM started'
}
