usage(){
  cat <<'EOF2'
Commands:
  (no command)       Run interactive wizard

  up [demo [light|full]|trustpoint|db|mail|sftp|worker|prometheus|grafana|monitoring] [--nowait]
  down [demo [light|full]|trustpoint|db|mail|sftp|worker|prometheus|grafana|monitoring]
  logs [trustpoint|db|mail|sftp|worker|prometheus|grafana]
  status
  nuke
  help

Demo presets:
  up demo light      trustpoint + PostgreSQL
  up demo            trustpoint + PostgreSQL + Mailpit + SFTPGo + workflows2 worker
  up demo full       demo + Prometheus + Grafana

Also supported (legacy): --only trustpoint|db|mail|sftp|worker|demo
EOF2
}

map_demo_preset_to_flags(){
  local preset="${1:-default}"
  case "$preset" in
    light)
      DEMO_PRESET="light"
      ONLY_APP=true
      ONLY_DB=true
      ;;
    default|demo)
      DEMO_PRESET="demo"
      ONLY_APP=true
      ONLY_DB=true
      ONLY_MAIL=true
      ONLY_SFTP=true
      ONLY_WF2_WORKER=true
      ;;
    full)
      DEMO_PRESET="full"
      ONLY_APP=true
      ONLY_DB=true
      ONLY_MAIL=true
      ONLY_SFTP=true
      ONLY_WF2_WORKER=true
      ONLY_PROMETHEUS=true
      ONLY_GRAFANA=true
      ;;
    *)
      die "Unknown demo preset: $preset (use light|full, or omit it for default demo)"
      ;;
  esac
}

map_only_to_flags(){
  case "$1" in
    demo) map_demo_preset_to_flags default ;;
    demo-light|light) map_demo_preset_to_flags light ;;
    demo-full|full) map_demo_preset_to_flags full ;;
    trustpoint|app) ONLY_APP=true ;;
    db) ONLY_DB=true ;;
    mail) ONLY_MAIL=true ;;
    sftp) ONLY_SFTP=true ;;
    worker) ONLY_WF2_WORKER=true ;;
    prometheus|prom) ONLY_PROMETHEUS=true ;;
    grafana) ONLY_GRAFANA=true ;;
    monitoring|metrics) ONLY_PROMETHEUS=true; ONLY_GRAFANA=true ;;
    *) die "Unknown target: $1 (use demo|trustpoint|db|mail|sftp|worker|prometheus|grafana|monitoring)" ;;
  esac
}

set_targets_from_args(){
  local any=false
  while [[ $# -gt 0 ]]; do
    case "$1" in
      demo)
        if [[ "${2:-}" == "light" || "${2:-}" == "full" ]]; then
          map_demo_preset_to_flags "$2"
          shift 2
        else
          map_demo_preset_to_flags default
          shift
        fi
        any=true
        ;;
      demo-light|demo-full|light|full|trustpoint|app|db|mail|sftp|worker|prometheus|prom|grafana|monitoring|metrics)
        map_only_to_flags "$1"
        any=true
        shift
        ;;
      --only)
        map_only_to_flags "${2:-}"
        any=true
        shift 2
        ;;
      --nowait)
        NOWAIT=true
        shift
        ;;
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
