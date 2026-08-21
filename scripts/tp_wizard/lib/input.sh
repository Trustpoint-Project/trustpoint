#!/usr/bin/env bash

ask() { local prompt="$1" default="${2:-}"; read -r -p "$prompt [$default] > " REPLY || true; REPLY="${REPLY:-$default}"; }
ask_yes_no() { local prompt="$1" default="${2:-y}"; read -r -p "$prompt [$default] > " REPLY || true; REPLY="${REPLY:-$default}"; [[ "$REPLY" =~ ^[Yy] ]]; }
