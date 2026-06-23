down_selected(){
  local done=false
  $ONLY_APP   && { stop_one trustpoint; stop_one "$WF2_WORKER_NAME"; done=true; }
  $ONLY_DB    && stop_one postgres   && done=true
  $ONLY_MAIL  && stop_one mailpit    && done=true
  $ONLY_SFTP  && stop_one sftpgo     && done=true
  $ONLY_WF2_WORKER && stop_one "$WF2_WORKER_NAME" && done=true
  $ONLY_PROMETHEUS && stop_one prometheus && done=true
  $ONLY_GRAFANA && stop_one grafana && done=true
  $done || { stop_one trustpoint; stop_one postgres; stop_one mailpit; stop_one sftpgo; stop_one "$WF2_WORKER_NAME"; stop_one prometheus; stop_one grafana; }
  ok "Stopped."
}

cmd_down(){
  set_targets_from_args "$@"
  down_selected
}
