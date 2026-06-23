#!/usr/bin/env bash
# tp_wizard.sh — public entrypoint for the trustpoint setup wizard
set -euo pipefail

TP_WIZARD_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export TP_WIZARD_ROOT

source "${TP_WIZARD_ROOT}/scripts/tp_wizard/bootstrap.sh"

tp_main "$@"
