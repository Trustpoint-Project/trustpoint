#!/usr/bin/env bash

require_command() { command -v "$1" >/dev/null 2>&1 || die "Required command not found: $1"; }
preflight() { require_command docker; docker info >/dev/null 2>&1 || die 'Docker daemon is not reachable'; }
