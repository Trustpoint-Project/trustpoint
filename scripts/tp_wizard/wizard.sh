wizard(){
  echo "$(bold)trustpoint Setup Wizard$(rst)"
  ensure_network
  step_enable_trustpoint
  step_trustpoint_source
  step_enable_postgres
  step_postgres_config
  step_app_db_binding
  mailpit_prompt_config
  sftpgo_prompt_config
  step_workflows2_worker
  show_plan
  ask_yes_no "Proceed with these settings?" "y" || { warn "Aborted by user."; exit 1; }
  runtime_start_enabled
}
