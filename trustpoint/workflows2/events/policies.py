# workflows2/events/policies.py
from __future__ import annotations

from workflows2.compiler.step_types import StepTypes

# A sane baseline for most events
BASE_AUTOMATION: set[str] = {
    StepTypes.SET,
    StepTypes.COMPUTE,
    StepTypes.LOGIC,
}

BASE_ADAPTERS: set[str] = {
    StepTypes.WEBHOOK,
    StepTypes.EMAIL,
}

# Terminal step TYPES were removed from the language.
# End states are now handled via:
# - implicit end / $end  => succeeded
# - $reject              => rejected
# - unexpected errors    => paused (retryable)
BASE_TERMINALS: set[str] = set()

# Common presets
AUTOMATION_NO_APPROVAL: set[str] = BASE_AUTOMATION | BASE_ADAPTERS
AUTOMATION_WITH_APPROVAL: set[str] = BASE_AUTOMATION | {StepTypes.APPROVAL} | BASE_ADAPTERS

# Event-specific (optional) aliases
STEPSET_AUTOMATION: set[str] = AUTOMATION_NO_APPROVAL
STEPSET_GATED_ENROLLMENT: set[str] = AUTOMATION_WITH_APPROVAL
