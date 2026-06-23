mailpit_prompt_config(){
  EN_MAILPIT=$(ask_yes_no "Enable Mailpit (demo SMTP inbox)?" "n" && echo true || echo false)
  if $EN_MAILPIT; then
    MAILPIT_SMTP_PORT="$(ask_free_port 'Mailpit SMTP host port' "$MAILPIT_SMTP_PORT")"
    MAILPIT_UI_PORT="$(ask_free_port 'Mailpit UI host port' "$MAILPIT_UI_PORT")"
  fi
}

start_mailpit(){
  $EN_MAILPIT || return 0
  local name="mailpit"
  stop_one "$name"
  if port_in_use "$MAILPIT_SMTP_PORT"; then die "Host port ${MAILPIT_SMTP_PORT} in use (Mailpit SMTP)."; fi
  if port_in_use "$MAILPIT_UI_PORT"; then die "Host port ${MAILPIT_UI_PORT} in use (Mailpit UI)."; fi
  log "Starting Mailpit..."
  docker run -d --name "$name" --network "$NET" \
    -p "${MAILPIT_SMTP_PORT}:1025" \
    -p "${MAILPIT_UI_PORT}:8025" \
    "$MAILPIT_IMAGE" >/dev/null
}


mailpit_has_subject(){
  local subject="$1"
  have curl || return 2
  local until=$(( $(date +%s) + MAILPIT_PROBE_TIMEOUT ))
  local api="http://127.0.0.1:${MAILPIT_UI_PORT}/api/v1/messages"
  while (( $(date +%s) < until )); do
    if curl -fsS "$api" 2>/dev/null | grep -Fq "$subject"; then
      return 0
    fi
    sleep 1
  done
  return 1
}


probe_mailpit_from_container(){
  local container="$1" label="$2"
  exists "$container" || return 0

  local subject="trustpoint wizard ${label} mailpit probe $(date +%s)"
  log "Sending Mailpit probe email from ${label} container..."

  if ! docker exec -e "PROBE_SUBJECT=${subject}" "$container" bash -lc \
    'cd /var/www/html/trustpoint && uv run trustpoint/manage.py shell -c '\''import os; from django.conf import settings; from django.core.mail import send_mail; subject=os.environ["PROBE_SUBJECT"]; send_mail(subject, "Trustpoint Mailpit probe.", getattr(settings, "DEFAULT_FROM_EMAIL", None), ["demo@trustpoint.local"], fail_silently=False)'\''' \
    >/dev/null 2>&1; then
    warn "Mailpit probe failed from ${label} container."
    return 1
  fi

  if ! have curl; then
    warn "curl not found on host; Mailpit probe from ${label} was sent but API verification was skipped."
    return 0
  fi

  if mailpit_has_subject "$subject"; then
    ok "Mailpit received the ${label} probe email."
    return 0
  fi

  warn "Mailpit SMTP accepted the ${label} probe email, but it did not appear in the Mailpit UI within ${MAILPIT_PROBE_TIMEOUT}s."
  return 1
}


verify_mailpit_delivery(){
  $EN_MAILPIT || return 0
  $EN_APP && probe_mailpit_from_container trustpoint "web" || true
  $EN_WF2_WORKER && probe_mailpit_from_container "$WF2_WORKER_NAME" "workflows2-worker" || true
}
