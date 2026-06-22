cmd_demo(){
  local preset="default"
  local preset_seen=false

  while [[ $# -gt 0 ]]; do
    case "$1" in
      light|full)
        if $preset_seen; then
          die "Only one demo preset is allowed."
        fi
        preset="$1"
        preset_seen=true
        shift
        ;;
      --skip-setup|--skip-trustpoint-setup|--no-skip-setup|--no-skip-trustpoint-setup|--nowait)
        set_common_runtime_flag "$1"
        shift
        ;;
      demo|default)
        if $preset_seen; then
          die "Only one demo preset is allowed."
        fi
        preset="default"
        preset_seen=true
        shift
        ;;
      *)
        die "Unknown demo option/preset: $1 (use light|full, --skip-setup, --no-skip-setup, --nowait)"
        ;;
    esac
  done

  map_demo_preset_to_flags "$preset"
  demo_apply_defaults
  runtime_start_selected
}

demo_apply_defaults(){
  # Demo mode must be non-interactive. Use deterministic defaults.
  DB_INTERNAL=true
  DB_HOST="$DEF_DB_HOST_INTERNAL"

  APP_DB_NAME="$DB_NAME"
  APP_DB_USER="$DB_USER"
  APP_DB_PASS="$DB_PASS"
  APP_DB_HOST="$DEF_DB_HOST_INTERNAL"
  APP_DB_PORT=5432

  # Demo mode should run the current checkout by default.
  # Set TP_WIZARD_DEMO_PULL=true to pull an image instead.
  if bool_env_true "${TP_WIZARD_DEMO_PULL:-false}"; then
    BUILD_LOCAL=false
    APP_IMAGE="${TP_REPO}:${TP_WIZARD_DEMO_IMAGE_TAG:-latest}"
  else
    BUILD_LOCAL=true
    APP_IMAGE="trustpoint:local"
  fi
}
