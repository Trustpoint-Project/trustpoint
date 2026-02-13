"""Test suite for security manager."""

from unittest.mock import Mock, patch

from django.test import TestCase
from management.models import SecurityConfig
from management.security import LEVEL_FEATURE_MAP
from management.security.features import AutoGenPkiFeature, SecurityFeature
from management.security.manager import SecurityManager


class MockSecurityFeature1(SecurityFeature):
    """Mock security feature for testing."""

    verbose_name = 'Mock Feature 1'
    db_field_name = 'mock_feature_1'

    def enable(self, **kwargs: object) -> None:
        """Mock enable method."""
        pass

    def disable(self, **kwargs: object) -> None:
        """Mock disable method."""
        pass

    def is_enabled(self) -> bool:
        """Mock is_enabled method."""
        return True


class MockSecurityFeature2(SecurityFeature):
    """Mock security feature for testing."""

    verbose_name = 'Mock Feature 2'
    db_field_name = 'mock_feature_2'

    def enable(self, **kwargs: object) -> None:
        """Mock enable method."""
        pass

    def disable(self, **kwargs: object) -> None:
        """Mock disable method."""
        pass

    def is_enabled(self) -> bool:
        """Mock is_enabled method."""
        return False


class SecurityManagerTest(TestCase):
    """Test suite for SecurityManager."""

    def setUp(self):
        """Set up test fixtures."""
        self.manager = SecurityManager()
        self.security_config = SecurityConfig.objects.create(
            security_mode=SecurityConfig.SecurityModeChoices.LOW,
            auto_gen_pki=False,
        )

    def test_get_security_level_returns_current_level(self):
        """Test get_security_level returns the current security mode."""
        self.assertEqual(self.manager.get_security_level(), SecurityConfig.SecurityModeChoices.LOW)

    def test_get_security_level_with_different_modes(self):
        """Test get_security_level with different security modes."""
        for mode in SecurityConfig.SecurityModeChoices:
            self.security_config.security_mode = mode
            self.security_config.save()
            self.assertEqual(self.manager.get_security_level(), mode)

    def test_get_security_config_model_returns_config(self):
        """Test get_security_config_model returns SecurityConfig instance."""
        config = self.manager.get_security_config_model()
        self.assertIsInstance(config, SecurityConfig)
        self.assertEqual(config, self.security_config)

    def test_is_feature_allowed_returns_true_for_dev_mode(self):
        """Test is_feature_allowed always returns True in DEV mode."""
        self.security_config.security_mode = SecurityConfig.SecurityModeChoices.DEV
        self.security_config.save()

        # Any feature should be allowed in DEV mode
        self.assertTrue(self.manager.is_feature_allowed(MockSecurityFeature1))
        self.assertTrue(self.manager.is_feature_allowed(AutoGenPkiFeature))

    def test_is_feature_allowed_with_feature_class(self):
        """Test is_feature_allowed works with feature class."""
        self.security_config.security_mode = SecurityConfig.SecurityModeChoices.LOW
        self.security_config.save()

        # AutoGenPkiFeature is in LOW_FEATURES
        self.assertTrue(self.manager.is_feature_allowed(AutoGenPkiFeature))

    def test_is_feature_allowed_with_feature_instance(self):
        """Test is_feature_allowed works with feature instance."""
        self.security_config.security_mode = SecurityConfig.SecurityModeChoices.LOW
        self.security_config.save()

        feature_instance = AutoGenPkiFeature()
        self.assertTrue(self.manager.is_feature_allowed(feature_instance))

    def test_is_feature_allowed_returns_false_when_not_allowed(self):
        """Test is_feature_allowed returns False when feature not in allowed set."""
        self.security_config.security_mode = SecurityConfig.SecurityModeChoices.HIGHEST
        self.security_config.save()

        # AutoGenPkiFeature is not in HIGHEST_FEATURES
        self.assertFalse(self.manager.is_feature_allowed(AutoGenPkiFeature))

    def test_is_feature_allowed_with_target_level_parameter(self):
        """Test is_feature_allowed with explicit target_level parameter."""
        # Current mode is LOW, but we check against HIGHEST
        self.security_config.security_mode = SecurityConfig.SecurityModeChoices.LOW
        self.security_config.save()

        # AutoGenPkiFeature not allowed at HIGHEST level
        result = self.manager.is_feature_allowed(
            AutoGenPkiFeature, target_level=SecurityConfig.SecurityModeChoices.HIGHEST
        )
        self.assertFalse(result)

        # AutoGenPkiFeature allowed at LOW level
        result = self.manager.is_feature_allowed(AutoGenPkiFeature, target_level=SecurityConfig.SecurityModeChoices.LOW)
        self.assertTrue(result)

    def test_is_feature_allowed_with_target_level_dev(self):
        """Test is_feature_allowed with target_level=DEV returns True."""
        self.security_config.security_mode = SecurityConfig.SecurityModeChoices.HIGHEST
        self.security_config.save()

        # Even though current mode is HIGHEST, checking against DEV should return True
        result = self.manager.is_feature_allowed(AutoGenPkiFeature, target_level=SecurityConfig.SecurityModeChoices.DEV)
        self.assertTrue(result)

    def test_get_features_to_disable_returns_correct_features(self):
        """Test get_features_to_disable returns features not allowed at given level."""
        # AutoGenPkiFeature is in LOW but not in HIGHEST
        features_to_disable = SecurityManager.get_features_to_disable(SecurityConfig.SecurityModeChoices.HIGHEST)

        self.assertIn(AutoGenPkiFeature, features_to_disable)

    def test_get_features_to_disable_returns_empty_for_dev(self):
        """Test get_features_to_disable returns empty list for DEV mode."""
        features_to_disable = SecurityManager.get_features_to_disable(SecurityConfig.SecurityModeChoices.DEV)

        # No features should be disabled in DEV mode
        # (DEV_FEATURES - DEV_FEATURES = empty set)
        self.assertEqual(len(features_to_disable), 0)

    def test_get_features_to_disable_with_different_levels(self):
        """Test get_features_to_disable with different security levels."""
        # LOW should have fewer features to disable than HIGHEST
        low_disabled = SecurityManager.get_features_to_disable(SecurityConfig.SecurityModeChoices.LOW)
        highest_disabled = SecurityManager.get_features_to_disable(SecurityConfig.SecurityModeChoices.HIGHEST)

        # HIGHEST should have more (or equal) features to disable
        self.assertGreaterEqual(len(highest_disabled), len(low_disabled))

    @patch.object(AutoGenPkiFeature, 'disable')
    def test_reset_settings_disables_features(self, mock_disable):
        """Test reset_settings calls disable on features that are not allowed."""
        # Set to LOW (AutoGenPkiFeature enabled), then reset to HIGHEST (AutoGenPkiFeature disabled)
        self.security_config.security_mode = SecurityConfig.SecurityModeChoices.LOW
        self.security_config.save()

        self.manager.reset_settings(SecurityConfig.SecurityModeChoices.HIGHEST)

        # AutoGenPkiFeature.disable should have been called
        mock_disable.assert_called_once()

    @patch.object(AutoGenPkiFeature, 'disable')
    def test_reset_settings_does_not_disable_allowed_features(self, mock_disable):
        """Test reset_settings does not disable features that remain allowed."""
        # Set to HIGHEST, then reset to LOW (AutoGenPkiFeature now allowed)
        self.security_config.security_mode = SecurityConfig.SecurityModeChoices.HIGHEST
        self.security_config.save()

        self.manager.reset_settings(SecurityConfig.SecurityModeChoices.LOW)

        # AutoGenPkiFeature.disable should not be called (it's being allowed, not disabled)
        mock_disable.assert_not_called()

    @patch.object(MockSecurityFeature1, 'enable')
    def test_enable_feature_calls_enable_when_allowed(self, mock_enable):
        """Test enable_feature calls enable method when feature is allowed."""
        self.security_config.security_mode = SecurityConfig.SecurityModeChoices.DEV
        self.security_config.save()

        self.manager.enable_feature(MockSecurityFeature1)

        mock_enable.assert_called_once()

    @patch.object(AutoGenPkiFeature, 'enable')
    def test_enable_feature_does_not_call_enable_when_not_allowed(self, mock_enable):
        """Test enable_feature does not call enable when feature is not allowed."""
        self.security_config.security_mode = SecurityConfig.SecurityModeChoices.HIGHEST
        self.security_config.save()

        # AutoGenPkiFeature not allowed at HIGHEST
        self.manager.enable_feature(AutoGenPkiFeature)

        mock_enable.assert_not_called()

    @patch.object(MockSecurityFeature1, 'enable')
    def test_enable_feature_with_kwargs(self, mock_enable):
        """Test enable_feature passes kwargs to enable method."""
        self.security_config.security_mode = SecurityConfig.SecurityModeChoices.DEV
        self.security_config.save()

        kwargs = {'key': 'value', 'number': 42}
        self.manager.enable_feature(MockSecurityFeature1, kwargs=kwargs)

        mock_enable.assert_called_once_with(**kwargs)

    @patch.object(MockSecurityFeature1, 'enable')
    def test_enable_feature_with_none_kwargs(self, mock_enable):
        """Test enable_feature calls enable without kwargs when kwargs is None."""
        self.security_config.security_mode = SecurityConfig.SecurityModeChoices.DEV
        self.security_config.save()

        self.manager.enable_feature(MockSecurityFeature1, kwargs=None)

        # Should call enable without any arguments
        mock_enable.assert_called_once_with()

    @patch.object(MockSecurityFeature1, 'enable')
    def test_enable_feature_with_feature_instance(self, mock_enable):
        """Test enable_feature works with feature instance."""
        self.security_config.security_mode = SecurityConfig.SecurityModeChoices.DEV
        self.security_config.save()

        feature_instance = MockSecurityFeature1()
        self.manager.enable_feature(feature_instance)

        mock_enable.assert_called_once()

    def test_is_feature_allowed_handles_string_security_level(self):
        """Test is_feature_allowed correctly handles string security level values."""
        # The security_mode in DB is stored as string ('0', '1', etc.)
        self.security_config.security_mode = '1'  # LOW
        self.security_config.save()

        # Should work with string value
        self.assertTrue(self.manager.is_feature_allowed(AutoGenPkiFeature))

    def test_level_feature_map_contains_all_security_modes(self):
        """Test LEVEL_FEATURE_MAP contains entries for all security modes."""
        for mode in SecurityConfig.SecurityModeChoices:
            self.assertIn(mode, LEVEL_FEATURE_MAP)

    def test_level_feature_map_dev_has_all_features(self):
        """Test DEV mode has the most features in LEVEL_FEATURE_MAP."""
        dev_features = LEVEL_FEATURE_MAP[SecurityConfig.SecurityModeChoices.DEV]

        # DEV should have all or most features
        for mode in SecurityConfig.SecurityModeChoices:
            mode_features = LEVEL_FEATURE_MAP[mode]
            # DEV should have at least as many features as any other mode
            # (or be a superset)
            if mode != SecurityConfig.SecurityModeChoices.DEV:
                self.assertTrue(dev_features.issuperset(mode_features) or dev_features == mode_features)
