#!/usr/bin/env bash

command_nuke() {
  read -r -p 'Remove Trustpoint containers, network, DB volume, generated files, HSM, SFTPGo data, and workflow data? [y/N] ' answer || true
  [[ "$answer" == y ]] || return 0
  read -r -p 'Are you sure? This is destructive. [y/N] ' answer || true
  [[ "$answer" == y ]] || return 0

  compose_down --volumes --remove-orphans
  runtime_stop trustpoint db mail sftp worker softhsm monitoring
  docker volume rm trustpoint_postgres_data >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
  for path in "$GENERATED_ROOT" "$LOCAL_HSM_ROOT" "$SFTPGO_ROOT" "$WF2_ROOT"; do
    [[ -e "$path" ]] || continue
    docker run --rm -v "$path:/cleanup" debian:trixie-slim sh -c 'rm -rf /cleanup/* /cleanup/.[!.]* /cleanup/..?*' >/dev/null 2>&1 || true
    rm -rf "$path" 2>/dev/null || true
  done
  ok 'Project resources removed'
}
