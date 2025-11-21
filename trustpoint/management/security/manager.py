"""Logic managing the security level setting of the Trustpoint."""

from __future__ import annotations

from typing import TYPE_CHECKING

from trustpoint.logger import LoggerMixin

from management.models import SecurityConfig
from management.security import LEVEL_FEATURE_MAP

if TYPE_CHECKING:
    from management.security.features import SecurityFeature


class SecurityManager(LoggerMixin):
    """Manages the security level setting of the Trustpoint."""

    def is_feature_allowed(
        self, feature: type[SecurityFeature] | SecurityFeature, target_level: None | str = None
    ) -> bool:
        """Checks if the specified feature is allowed under the given security level.

        If 'target_level' is None, the current security level is used.

        Args:
            feature: Either a SecurityFeature class or instance
            target_level: The security level to check against, or None for current level

        Returns:
            True if the feature is allowed at the specified security level
        """
        sec_level = self.get_security_level() if target_level is None else target_level

        if sec_level == SecurityConfig.SecurityModeChoices.DEV:
            return True

        # Convert or cast sec_level to actual SecurityModeChoices if needed:
        # If sec_level is just a string like '1', get the enumerated type:
        level_choice = SecurityConfig.SecurityModeChoices(sec_level)

        # If the level is defined in the dictionary, check membership
        allowed_features = LEVEL_FEATURE_MAP.get(level_choice, set())

        # Handle both class and instance - check the class type
        feature_class = feature if isinstance(feature, type) else type(feature)
        return feature_class in allowed_features

    def get_security_level(self) -> str:
        """Returns the string representation of the security_mode, e.g. '0', '1', etc."""
        return self.get_security_config_model().security_mode

    @classmethod
    def get_features_to_disable(cls, sec_level: str) -> list[SecurityFeature]:
        """Returns a list of features that must be disabled at the given security level."""
        dev_features = LEVEL_FEATURE_MAP[SecurityConfig.SecurityModeChoices.DEV]
        level_choice = SecurityConfig.SecurityModeChoices(sec_level)
        valid_features = LEVEL_FEATURE_MAP.get(level_choice, set())

        # The difference is the set of features that are NOT allowed at this level.
        must_disable = dev_features - valid_features
        return list(must_disable)

    def reset_settings(self, new_sec_mode: str) -> None:
        """Disables any feature that is not allowed by the new security mode."""
        features_to_disable = self.get_features_to_disable(new_sec_mode)
        for feature in features_to_disable:
            self.logger.info('Disabling Feature: %s', feature)
            feature.disable()

    def get_security_config_model(self) -> SecurityConfig:
        """Returns the model holding the security settings."""
        return SecurityConfig.objects.first()

    def enable_feature(self, feature: type[SecurityFeature] | SecurityFeature, kwargs: dict | None = None) -> None:
        """Enables a feature if it is allowed at the current security level.

        Args:
            feature: Either a SecurityFeature class or instance
            kwargs: Keyword arguments to pass to the enable method
        """
        if self.is_feature_allowed(feature):
            if kwargs is None:
                feature.enable()
            else:
                feature.enable(**kwargs)
