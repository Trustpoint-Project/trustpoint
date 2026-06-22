cmd_status(){
  [[ $# -eq 0 ]] || die "status does not take targets. Use it without arguments."
  show_runtime_status
}
