#!/usr/bin/env bash

interactive_wizard() {
  state_reset
  printf 'Trustpoint setup wizard\n\n'
  read -r -p 'Start PostgreSQL? [Y/n] ' answer || true
  [[ "${answer:-y}" =~ ^[Yy] ]] && state_add db
  read -r -p 'Start Trustpoint? [Y/n] ' answer || true
  [[ "${answer:-y}" =~ ^[Yy] ]] && state_add trustpoint
  read -r -p 'Start Mailpit? [y/N] ' answer || true
  [[ "${answer:-n}" =~ ^[Yy] ]] && state_add mail
  read -r -p 'Start SFTPGo? [y/N] ' answer || true
  [[ "${answer:-n}" =~ ^[Yy] ]] && state_add sftp
  read -r -p 'Start workflows2 worker? [y/N] ' answer || true
  [[ "${answer:-n}" =~ ^[Yy] ]] && state_add worker
  read -r -p 'Start monitoring? [y/N] ' answer || true
  [[ "${answer:-n}" =~ ^[Yy] ]] && ENABLE_METRICS=true && state_add monitoring
  runtime_start
  summary
}
