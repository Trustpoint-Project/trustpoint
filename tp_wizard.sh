#!/usr/bin/env bash
set -euo pipefail

TP_WIZARD_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/scripts/tp_wizard" && pwd)"
# shellcheck source=/dev/null
source "${TP_WIZARD_ROOT}/main.sh"
tp_wizard_main "$@"
