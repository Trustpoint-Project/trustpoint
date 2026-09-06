#!/usr/bin/env bash

start_mailpit() {
  remove_container mailpit
  start_container mailpit -p "${MAILPIT_SMTP_PORT}:1025" -p "${MAILPIT_UI_PORT}:8025" "$MAILPIT_IMAGE"
  ok 'Mailpit started'
}
