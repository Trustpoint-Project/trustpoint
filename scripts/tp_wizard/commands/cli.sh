#!/usr/bin/env bash
# shellcheck disable=SC2034 # CLI assignments update shared runtime state.

cli_help() {
  printf '%s\n' 'Usage:' './tp_wizard.sh' './tp_wizard.sh demo [light|full] [--skip-wizard] [--nowait]' './tp_wizard.sh up trustpoint|db|mail|sftp|worker|prometheus|grafana|monitoring [--skip-wizard] [--nowait]' './tp_wizard.sh down ...' './tp_wizard.sh logs [service]' './tp_wizard.sh status' './tp_wizard.sh nuke' '' '--skip-wizard enables automatic Trustpoint setup. --skip-setup remains an alias.'
}

demo_help() {
  cat <<'EOF'
Demo presets:

  demo light
      Trustpoint and PostgreSQL only.

  demo
      Trustpoint, PostgreSQL, Mailpit, and SFTPGo.

  demo full
      The standard demo plus provisioned Prometheus and Grafana. With
      --skip-wizard, Trustpoint metrics are enabled automatically.

  worker
      Is never started by a demo preset. Add it explicitly with:
      ./tp_wizard.sh up worker

All demo presets build the local Trustpoint image and leave the Trustpoint
in-app setup wizard enabled by default. Use --skip-wizard for automatic setup,
or --nowait to return immediately after containers are started.

Examples:
  ./tp_wizard.sh demo light
  ./tp_wizard.sh demo
  ./tp_wizard.sh demo full --skip-wizard
EOF
}

demo_config() {
  state_reset
  TP_INJECT_DEMO_DATA=true
  case "${1:-demo}" in
    light) state_add db; state_add trustpoint ;;
    demo) state_add db; state_add trustpoint; state_add mail; state_add sftp ;;
    full) ENABLE_METRICS=true; state_add db; state_add trustpoint; state_add mail; state_add sftp; state_add monitoring ;;
    *) die "Unknown demo preset: ${1:-}" ;;
  esac
}

cli_demo() {
  local preset=demo
  [[ "${1:-}" == help || "${1:-}" == --help ]] && { demo_help; return 0; }
  [[ "${1:-}" != --* && $# -gt 0 ]] && preset="$1" && shift
  demo_config "$preset"
  while (($#)); do
    case "$1" in
      --nowait) NOWAIT=true ;;
      --skip-wizard|--skip-setup) TP_AUTO_SETUP=true ;;
      --no-skip-wizard|--no-skip-setup) TP_AUTO_SETUP=false ;;
      *) die "Unknown demo option: $1" ;;
    esac
    shift
  done
  runtime_start; summary
}

cli_up() {
  [[ "${1:-}" != demo ]] || die "'up demo ...' is not supported; use './tp_wizard.sh demo full'."
  state_reset
  while (($#)); do
    case "$1" in
      trustpoint) state_add trustpoint ;;
      db) state_add db ;;
      mail) state_add mail ;;
      sftp) state_add sftp ;;
      worker) state_add worker ;;
      prometheus|grafana|monitoring) ENABLE_METRICS=true; state_add monitoring ;;
      --nowait) NOWAIT=true ;;
      --skip-wizard|--skip-setup) TP_AUTO_SETUP=true ;;
      --no-skip-wizard|--no-skip-setup) TP_AUTO_SETUP=false ;;
      *) die "Unknown up target: $1" ;;
    esac
    shift
  done
  runtime_start; summary
}

cli_down() { [[ $# -gt 0 ]] || set -- trustpoint db mail sftp worker monitoring; runtime_stop "$@"; }
cli_logs() { preflight; local name="${1:-trustpoint}"; case "$name" in db) name=postgres ;; mail) name=mailpit ;; sftp) name=sftpgo ;; worker) name="$WF2_WORKER_NAME" ;; monitoring) name="$PROMETHEUS_NAME" ;; esac; docker logs -f "$name"; }
cli_status() {
  preflight
  state_reset
  STATUS_ONLY=true
  container_exists trustpoint && state_add trustpoint
  container_exists postgres && state_add db
  container_exists mailpit && state_add mail
  container_exists sftpgo && state_add sftp
  container_exists "$WF2_WORKER_NAME" && state_add worker
  container_exists "$SOFTHSM_NAME" && state_add softhsm
  container_exists "$PROMETHEUS_NAME" && state_add monitoring
  compose_service_containers trustpoint-worker | grep -q . && state_add worker || true
  summary
}
cli_dispatch() {
  case "${1:-}" in
    '') interactive_wizard ;;
    help|-h|--help) cli_help ;;
    demo) shift; cli_demo "$@" ;;
    up) shift; cli_up "$@" ;;
    down) shift; cli_down "$@" ;;
    logs) shift; cli_logs "$@" ;;
    status) shift; [[ $# -eq 0 ]] || die 'status takes no arguments'; cli_status ;;
    nuke) command_nuke ;;
    *) die "Unknown command: $1" ;;
  esac
}
