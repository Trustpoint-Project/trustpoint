"""Security management package."""

from management.models import SecurityConfig
from management.security.features import AutoGenPkiFeature

# 1) Minimal set: CRITICAL
CRITICAL_FEATURES = {None}

# 2) HARDENED inherits everything from CRITICAL
HARDENED_FEATURES = CRITICAL_FEATURES | {None}

# 3) INDUSTRIAL inherits from HARDENED
INDUSTRIAL_FEATURES = HARDENED_FEATURES | {None}

# 4) BROWNFIELD inherits from INDUSTRIAL
BROWNFIELD_FEATURES = INDUSTRIAL_FEATURES | {AutoGenPkiFeature}

# 5) LAB inherits from BROWNFIELD (all features available)
LAB_FEATURES = BROWNFIELD_FEATURES | {None}

LEVEL_FEATURE_MAP = {
    SecurityConfig.SecurityModeChoices.CRITICAL: CRITICAL_FEATURES,
    SecurityConfig.SecurityModeChoices.HARDENED: HARDENED_FEATURES,
    SecurityConfig.SecurityModeChoices.INDUSTRIAL: INDUSTRIAL_FEATURES,
    SecurityConfig.SecurityModeChoices.BROWNFIELD: BROWNFIELD_FEATURES,
    SecurityConfig.SecurityModeChoices.LAB: LAB_FEATURES,
}
