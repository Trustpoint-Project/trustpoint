configure_selected(){
  if $ONLY_DB; then
    EN_PG=true
    DB_INTERNAL=true
  fi
  $ONLY_MAIL && EN_MAILPIT=true
  $ONLY_SFTP && EN_SFTPGO=true

  if $ONLY_APP; then
    EN_APP=true
    configure_app_image_prompt
    EN_WF2_WORKER=$(
      ask_yes_no "Delegate workflows2 tasks to a dedicated worker container?" "n" && echo true || echo false
    )
  elif $ONLY_WF2_WORKER; then
    EN_WF2_WORKER=true
    configure_app_image_prompt
  fi

  if $ONLY_APP || $ONLY_WF2_WORKER; then
    if $DB_INTERNAL; then
      APP_DB_HOST="$DEF_DB_HOST_INTERNAL"
      APP_DB_PORT=5432
    else
      APP_DB_HOST="$DB_HOST"
      APP_DB_PORT="$DB_PORT"
    fi
    APP_DB_NAME="$DB_NAME"
    APP_DB_USER="$DB_USER"
    APP_DB_PASS="$DB_PASS"
  fi
}


cmd_up(){
  set_targets_from_args "$@"
  configure_selected
  ensure_network
  runtime_start_selected
}
