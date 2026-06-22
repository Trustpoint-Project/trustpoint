# shellcheck shell=bash
# Load tp_wizard modules in dependency order.

source "${TP_WIZARD_ROOT}/scripts/tp_wizard/defaults.sh"
source "${TP_WIZARD_ROOT}/scripts/tp_wizard/state.sh"

source "${TP_WIZARD_ROOT}/scripts/tp_wizard/lib/ui.sh"
source "${TP_WIZARD_ROOT}/scripts/tp_wizard/lib/validation.sh"
source "${TP_WIZARD_ROOT}/scripts/tp_wizard/lib/ports.sh"
source "${TP_WIZARD_ROOT}/scripts/tp_wizard/lib/docker.sh"
source "${TP_WIZARD_ROOT}/scripts/tp_wizard/lib/input.sh"
source "${TP_WIZARD_ROOT}/scripts/tp_wizard/lib/env.sh"

source "${TP_WIZARD_ROOT}/scripts/tp_wizard/summary.sh"

source "${TP_WIZARD_ROOT}/scripts/tp_wizard/services/postgres.sh"
source "${TP_WIZARD_ROOT}/scripts/tp_wizard/services/trustpoint.sh"
source "${TP_WIZARD_ROOT}/scripts/tp_wizard/services/mailpit.sh"
source "${TP_WIZARD_ROOT}/scripts/tp_wizard/services/sftpgo.sh"
source "${TP_WIZARD_ROOT}/scripts/tp_wizard/services/workflows2_worker.sh"
source "${TP_WIZARD_ROOT}/scripts/tp_wizard/services/monitoring.sh"

source "${TP_WIZARD_ROOT}/scripts/tp_wizard/runtime.sh"
source "${TP_WIZARD_ROOT}/scripts/tp_wizard/wizard.sh"

source "${TP_WIZARD_ROOT}/scripts/tp_wizard/commands/up.sh"
source "${TP_WIZARD_ROOT}/scripts/tp_wizard/commands/down.sh"
source "${TP_WIZARD_ROOT}/scripts/tp_wizard/commands/logs.sh"
source "${TP_WIZARD_ROOT}/scripts/tp_wizard/commands/status.sh"
source "${TP_WIZARD_ROOT}/scripts/tp_wizard/commands/nuke.sh"

source "${TP_WIZARD_ROOT}/scripts/tp_wizard/cli.sh"
