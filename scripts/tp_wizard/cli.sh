usage(){
  cat <<'EOF2'
Commands:
  (no command)       Run interactive wizard

  demo [light|full] [--skip-setup|--no-skip-setup] [--nowait]
  up [trustpoint|db|mail|sftp|worker|prometheus|grafana|monitoring] [--skip-setup|--no-skip-setup] [--nowait]
  down [trustpoint|db|mail|sftp|worker|prometheus|grafana|monitoring]
  logs [trustpoint|db|mail|sftp|worker|prometheus|grafana]
  status
  nuke
  help

Demo presets:
  demo light         trustpoint + PostgreSQL
  demo               trustpoint + PostgreSQL + Mailpit + SFTPGo + workflows2 worker
  demo full          demo + Prometheus + Grafana

Notes:
  - Use `demo ...` for non-interactive demo presets.
  - Use `up ...` for individual containers/services only.
  - `up demo ...` is intentionally not supported.
  - Use `--skip-setup` to make trustpoint skip its in-app setup wizard.
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
    trustpoint|app) ONLY_APP=true ;;
    db) ONLY_DB=true ;;
    mail) ONLY_MAIL=true ;;
    sftp) ONLY_SFTP=true ;;
    worker) ONLY_WF2_WORKER=true ;;
    prometheus|prom) ONLY_PROMETHEUS=true ;;
    grafana) ONLY_GRAFANA=true ;;
    monitoring|metrics) ONLY_PROMETHEUS=true; ONLY_GRAFANA=true ;;
    demo|light|full|demo-light|demo-full)
      die "Demo presets are not valid for 'up'. Use './tp_wizard.sh demo [light|full]' instead."
      ;;
    *) die "Unknown target: $1 (use trustpoint|db|mail|sftp|worker|prometheus|grafana|monitoring)" ;;
  esac
}

set_common_runtime_flag(){
  case "$1" in
    --skip-setup|--skip-trustpoint-setup)
      TP_SKIP_SETUP_VALUE="true"
      ;;
    --no-skip-setup|--no-skip-trustpoint-setup)
      TP_SKIP_SETUP_VALUE="false"
      ;;
    --nowait)
      NOWAIT=true
      ;;
    *)
      return 1
      ;;
  esac
}

set_targets_from_args(){
  local any=false
  while [[ $# -gt 0 ]]; do
    case "$1" in
      trustpoint|app|db|mail|sftp|worker|prometheus|prom|grafana|monitoring|metrics)
        map_only_to_flags "$1"
        any=true
        shift
        ;;
      --only)
        [[ $# -ge 2 ]] || die "--only requires a target"
        map_only_to_flags "$2"
        any=true
        shift 2
        ;;
      --skip-setup|--skip-trustpoint-setup|--no-skip-setup|--no-skip-trustpoint-setup|--nowait)
        set_common_runtime_flag "$1"
        shift
        ;;
      demo|light|full|demo-light|demo-full)
        map_only_to_flags "$1"
        ;;
      *) die "Unknown option/target: $1" ;;
    esac
  done

  # Historical default for `up`: start trustpoint + DB when no target is given.
  if ! $any; then
    ONLY_APP=true
    ONLY_DB=true
  fi
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
    demo)
      preflight
      shift || true
      cmd_demo "$@"
      ;;
    up)
      if [[ "${2:-}" == "demo" || "${2:-}" == "light" || "${2:-}" == "full" || "${2:-}" == "demo-light" || "${2:-}" == "demo-full" ]]; then
        die "Demo presets are not valid for 'up'. Use './tp_wizard.sh demo [light|full]' instead."
      fi
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
