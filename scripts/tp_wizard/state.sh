#!/usr/bin/env bash
# shellcheck disable=SC2034 # Runtime state is intentionally shared across sourced modules.

NOWAIT=false
BUILD_LOCAL=true
ENABLE_METRICS=false
ENABLE_USB_PASSTHROUGH=false
STATUS_ONLY=false
SERVICES=()

state_reset() {
  SERVICES=()
  NOWAIT=false
  BUILD_LOCAL=true
  ENABLE_METRICS=false
  ENABLE_USB_PASSTHROUGH=false
  STATUS_ONLY=false
  TP_AUTO_SETUP=false
  TP_INJECT_DEMO_DATA=false
}

state_add() {
  local service="$1" existing
  for existing in "${SERVICES[@]}"; do [[ "$existing" == "$service" ]] && return; done
  SERVICES+=("$service")
}

state_has() {
  local expected="$1" service
  for service in "${SERVICES[@]}"; do
    [[ "$service" == "$expected" ]] && return 0
  done
  return 1
}
