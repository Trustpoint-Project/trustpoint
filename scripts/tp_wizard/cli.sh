usage(){
  cat <<'EOF2'
Commands:
  (no command)       Run interactive wizard
  up [demo|trustpoint|db|mail|sftp|worker] [--nowait]
  down [demo|trustpoint|db|mail|sftp|worker]
  logs [trustpoint|db|mail|sftp|worker]
  status
  nuke
  help

Also supported (legacy): --only trustpoint|db|mail|sftp|worker|demo
EOF2
}


map_only_to_flags(){
  case "$1" in
    demo)  ONLY_APP=true; ONLY_DB=true; ONLY_MAIL=true; ONLY_SFTP=true ;;
    trustpoint|app)  ONLY_APP=true ;;
    db)   ONLY_DB=true ;;
    mail) ONLY_MAIL=true ;;
    sftp) ONLY_SFTP=true ;;
    worker) ONLY_WF2_WORKER=true ;;
    *) die "Unknown target: $1 (use trustpoint|db|mail|sftp|worker|demo)";;
  esac
}


set_targets_from_args(){
  local any=false
  while [[ $# -gt 0 ]]; do
    case "$1" in
      demo|trustpoint|app|db|mail|sftp|worker) map_only_to_flags "$1"; any=true; shift ;;
      --only) map_only_to_flags "${2:-}"; any=true; shift 2 ;;
      --nowait) NOWAIT=true; shift ;;
      *) die "Unknown option/target: $1" ;;
    esac
  done
  if ! $any; then ONLY_APP=true; ONLY_DB=true; fi
}


tp_main(){
  local cmd="${1:-}"

  case "$cmd" in
    "" )
      preflight
      wizard
      ;;
    help|-h|--help)
      usage
      ;;
    up)
      preflight
      shift || true
      cmd_up "$@"
      ;;
    down)
      preflight
      shift || true
      cmd_down "$@"
      ;;
    logs)
      preflight
      shift || true
      cmd_logs "$@"
      ;;
    status)
      preflight
      shift || true
      cmd_status "$@"
      ;;
    nuke)
      preflight
      cmd_nuke
      ;;
    *)
      usage
      die "Unknown command: $cmd"
      ;;
  esac
}
