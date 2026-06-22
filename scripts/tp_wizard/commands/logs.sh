logs_selected(){
  local target="trustpoint"
  $ONLY_DB && target="postgres"
  $ONLY_MAIL && target="mailpit"
  $ONLY_SFTP && target="sftpgo"
  $ONLY_WF2_WORKER && target="$WF2_WORKER_NAME"
  exists "$target" || die "Container not found: $target"
  docker logs -f "$target"
}


cmd_logs(){
  set_targets_from_args "$@"
  logs_selected
}
