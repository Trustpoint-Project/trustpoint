#!/usr/bin/env bash

command_nuke() {
  local remove_env=false
  ask_yes_no 'Remove Trustpoint containers, network, DB volume, generated files, HSM, SFTPGo data, and workflow data?' n || return 0
  ask_yes_no "Also delete the wizard env overlay at $ENV_OVERLAY?" n && remove_env=true

  compose_down --volumes --remove-orphans
  runtime_stop trustpoint db mail sftp worker softhsm monitoring
  docker volume rm trustpoint_postgres_data >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
  for path in "$GENERATED_ROOT" "$LOCAL_HSM_ROOT" "$SFTPGO_ROOT" "$WF2_ROOT"; do
    [[ -e "$path" ]] || continue
    docker run --rm -v "$path:/cleanup" debian:trixie-slim sh -c 'rm -rf /cleanup/* /cleanup/.[!.]* /cleanup/..?*' >/dev/null 2>&1 || true
    rm -rf "$path" 2>/dev/null || true
  done
  $remove_env && rm -f "$ENV_OVERLAY"
  ok 'Project resources removed'
}
