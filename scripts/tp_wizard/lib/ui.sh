#!/usr/bin/env bash

log() { printf '%s\n' "$*" >&2; }
ok() { log "✔ $*"; }
warn() { log "⚠ $*"; }
die() { log "✖ $*"; return 1; }
mask() { local s="${1:-}"; if [[ ${#s} -le 2 ]]; then printf '**'; else printf '%*s%s' $((${#s}-2)) '' "${s: -2}" | tr ' ' '*'; fi; }
