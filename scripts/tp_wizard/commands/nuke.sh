nuke_cmd(){
  read -r -p "Remove ALL project containers, network, DB volume, ./sftpgo-data, and ./workflow2Folder? [y/N] " a; [[ "${a}" == "y" ]] || exit 0
  read -r -p "Are you sure? This is destructive. [y/N] " b; [[ "${b}" == "y" ]] || exit 0
  mapfile -t project_volumes < <(collect_project_volumes)
  stop_one trustpoint; stop_one postgres; stop_one mailpit; stop_one sftpgo; stop_one "$WF2_WORKER_NAME"
  docker network rm "$NET" >/dev/null 2>&1 || true
  for v in "${project_volumes[@]}"; do
    [[ -n "$v" ]] || continue
    docker volume rm "$v" >/dev/null 2>&1 || true
  done
  if [[ -d "$SFTPGO_ROOT" ]]; then rm -rf "$SFTPGO_ROOT"; fi
  if [[ -d "$WF2_FOLDER" ]]; then rm -rf "$WF2_FOLDER"; fi
  ok "Project resources removed."
}


cmd_nuke(){
  nuke_cmd
}
