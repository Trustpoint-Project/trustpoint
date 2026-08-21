#!/usr/bin/env bash
# shellcheck disable=SC2034 # Runtime state is intentionally shared across sourced modules.

MODE=""
NOWAIT=false
SKIP_SETUP=true
BUILD_LOCAL=true
ENABLE_METRICS=false
STATUS_ONLY=false
SERVICES=()

state_reset() {
  SERVICES=()
  NOWAIT=false
  SKIP_SETUP=true
  BUILD_LOCAL=true
  ENABLE_METRICS=false
  STATUS_ONLY=false
}

state_add() {
  local service="$1" existing
  for existing in "${SERVICES[@]}"; do [[ "$existing" == "$service" ]] && return; done
  SERVICES+=("$service")
}
