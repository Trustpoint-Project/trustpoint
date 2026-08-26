#!/usr/bin/env bash

ask() {
  local prompt="$1" default="${2:-}"
  read -r -p "$prompt${default:+ [$default]} > " REPLY || true
  REPLY="${REPLY:-$default}"
}

ask_yes_no() {
  local prompt="$1" default="${2:-y}" hint='[Y/n]'
  [[ "$default" =~ ^[Nn] ]] && hint='[y/N]'
  read -r -p "$prompt $hint > " REPLY || true
  REPLY="${REPLY:-$default}"
  [[ "$REPLY" =~ ^[Yy] ]]
}

ask_required() {
  local prompt="$1" default="${2:-}"
  while true; do
    ask "$prompt" "$default"
    [[ -n "$REPLY" ]] && return 0
    warn 'A value is required.'
  done
}

ask_port() {
  local prompt="$1" default="$2"
  while true; do
    ask "$prompt" "$default"
    [[ "$REPLY" =~ ^[0-9]+$ ]] && ((10#$REPLY >= 1 && 10#$REPLY <= 65535)) && return 0
    warn 'Enter a port between 1 and 65535.'
  done
}

ask_uint() {
  local prompt="$1" default="$2"
  while true; do
    ask "$prompt" "$default"
    [[ "$REPLY" =~ ^[0-9]+$ ]] && return 0
    warn 'Enter a non-negative whole number.'
  done
}

ask_password() {
  local prompt="$1" default="$2"
  while true; do
    ask "$prompt" "$default"
    ((${#REPLY} >= 6)) && return 0
    warn 'Password must contain at least 6 characters.'
  done
}
