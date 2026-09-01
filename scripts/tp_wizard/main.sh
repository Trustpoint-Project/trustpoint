#!/usr/bin/env bash
set -euo pipefail

TP_WIZARD_ROOT="${TP_WIZARD_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}"
source "${TP_WIZARD_ROOT}/defaults.sh"
source "${TP_WIZARD_ROOT}/state.sh"
source "${TP_WIZARD_ROOT}/lib/ui.sh"
source "${TP_WIZARD_ROOT}/lib/docker.sh"
source "${TP_WIZARD_ROOT}/lib/env.sh"
source "${TP_WIZARD_ROOT}/lib/input.sh"
source "${TP_WIZARD_ROOT}/lib/ports.sh"
source "${TP_WIZARD_ROOT}/lib/validation.sh"
source "${TP_WIZARD_ROOT}/services/postgres.sh"
source "${TP_WIZARD_ROOT}/services/trustpoint.sh"
source "${TP_WIZARD_ROOT}/services/mailpit.sh"
source "${TP_WIZARD_ROOT}/services/sftpgo.sh"
source "${TP_WIZARD_ROOT}/services/worker.sh"
source "${TP_WIZARD_ROOT}/services/softhsm.sh"
source "${TP_WIZARD_ROOT}/services/monitoring.sh"
source "${TP_WIZARD_ROOT}/runtime.sh"
source "${TP_WIZARD_ROOT}/summary.sh"
source "${TP_WIZARD_ROOT}/wizard.sh"
source "${TP_WIZARD_ROOT}/commands/cli.sh"
source "${TP_WIZARD_ROOT}/commands/nuke.sh"

tp_wizard_main() {
  cli_dispatch "$@"
}
