from settings.models import SecurityConfig
from settings.security.features import AutoGenPkiFeature

# 1) Minimal set: HIGHEST
HIGHEST_FEATURES = {None}

# 2) HIGH inherits everything from HIGHEST,
HIGH_FEATURES = HIGHEST_FEATURES | {None}

# 3) MEDIUM inherits from HIGH
MEDIUM_FEATURES = HIGH_FEATURES | {None}

# 4) LOW inherits from MEDIUM
LOW_FEATURES = MEDIUM_FEATURES | {AutoGenPkiFeature}

# 5) DEV inherits from LOW (All features available)
DEV_FEATURES = LOW_FEATURES | {None}

LEVEL_FEATURE_MAP = {
    SecurityConfig.SecurityModeChoices.HIGHEST: HIGHEST_FEATURES,
    SecurityConfig.SecurityModeChoices.HIGH: HIGH_FEATURES,
    SecurityConfig.SecurityModeChoices.MEDIUM: MEDIUM_FEATURES,
    SecurityConfig.SecurityModeChoices.LOW: LOW_FEATURES,
    SecurityConfig.SecurityModeChoices.DEV: DEV_FEATURES,
}
