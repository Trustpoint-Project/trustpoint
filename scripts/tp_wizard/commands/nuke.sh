nuke_remove_tree(){
  local path="$1"
  [[ -e "$path" ]] || return 0

  if rm -rf "$path" 2>/dev/null; then
    return 0
  fi

  return 1
}

nuke_remove_bind_mount_tree(){
  local path="$1" parent base
  [[ -e "$path" ]] || return 0

  if nuke_remove_tree "$path"; then
    return 0
  fi

  parent="$(dirname "$path")"
  base="$(basename "$path")"
  warn "Host user cannot remove ${path}; retrying cleanup through Docker..."
  if docker run --rm -v "${parent}:/cleanup" debian:trixie-slim \
    bash -lc 'rm -rf -- "/cleanup/$1"' _ "$base" >/dev/null; then
    return 0
  fi

  warn "Could not remove ${path}. Remove it manually with elevated permissions."
  return 1
}

nuke_cmd(){
  read -r -p "Remove ALL project containers, network, DB/Grafana volumes, ./sftpgo-data, ./workflow2Folder, ./var/hsm, and ./.tp_wizard? [y/N] " a
  [[ "${a}" == "y" ]] || exit 0
  read -r -p "Are you sure? This is destructive. [y/N] " b
  [[ "${b}" == "y" ]] || exit 0

  mapfile -t project_volumes < <(collect_project_volumes)
  stop_one trustpoint
  stop_one postgres
  stop_one mailpit
  stop_one sftpgo
  stop_one "$SOFTHSM_NAME"
  stop_one "$WF2_WORKER_NAME"
  stop_one prometheus
  stop_one grafana
  docker network rm "$NET" >/dev/null 2>&1 || true

  for v in "${project_volumes[@]}"; do
    [[ -n "$v" ]] || continue
    docker volume rm "$v" >/dev/null 2>&1 || true
  done

  nuke_remove_tree "$SFTPGO_ROOT"
  nuke_remove_bind_mount_tree "$LOCAL_HSM_ROOT"
  nuke_remove_tree "$WF2_FOLDER"
  nuke_remove_tree "$TP_WIZARD_GENERATED_ROOT"
  ok "Project resources removed."
}

cmd_nuke(){
  nuke_cmd
}
