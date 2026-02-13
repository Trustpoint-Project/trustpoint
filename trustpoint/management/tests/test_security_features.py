"""Test suite for security features."""

import threading
from unittest.mock import Mock, patch

from django.test import TestCase
from management.models import SecurityConfig
from management.security.features import AutoGenPkiFeature, SecurityFeature
from pki.util.keys import AutoGenPkiKeyAlgorithm


class MockSecurityFeature(SecurityFeature):
    """Mock security feature for testing."""

    verbose_name = 'Mock Feature'
    db_field_name = 'mock_feature'
    _enabled = False

    @classmethod
    def enable(cls, **kwargs: object) -> None:
        """Mock enable method."""
        cls._enabled = True

    @classmethod
    def disable(cls, **kwargs: object) -> None:
        """Mock disable method."""
        cls._enabled = False

    @classmethod
    def is_enabled(cls) -> bool:
        """Mock is_enabled method."""
        return cls._enabled


class SecurityFeatureTest(TestCase):
    """Test suite for SecurityFeature abstract base class."""

    def test_security_feature_is_abstract(self):
        """Test that SecurityFeature cannot be instantiated directly."""
        with self.assertRaises(TypeError):
            SecurityFeature()  # type: ignore

    def test_security_feature_has_verbose_name(self):
        """Test that SecurityFeature has verbose_name class attribute."""
        self.assertIsNone(SecurityFeature.verbose_name)

    def test_security_feature_has_db_field_name(self):
        """Test that SecurityFeature has db_field_name class attribute."""
        self.assertIsNone(SecurityFeature.db_field_name)

    def test_mock_security_feature_implements_interface(self):
        """Test that MockSecurityFeature correctly implements SecurityFeature interface."""
        feature = MockSecurityFeature()
        self.assertIsInstance(feature, SecurityFeature)
        self.assertEqual(feature.verbose_name, 'Mock Feature')
        self.assertEqual(feature.db_field_name, 'mock_feature')


class AutoGenPkiFeatureTest(TestCase):
    """Test suite for AutoGenPkiFeature."""

    def setUp(self):
        """Set up test fixtures."""
        # Create a SecurityConfig instance
        self.security_config = SecurityConfig.objects.create(
            security_mode=SecurityConfig.SecurityModeChoices.DEV,
            auto_gen_pki=False,
            auto_gen_pki_key_algorithm=AutoGenPkiKeyAlgorithm.RSA2048,
        )

    def test_verbose_name(self):
        """Test that AutoGenPkiFeature has correct verbose_name."""
        self.assertEqual(AutoGenPkiFeature.verbose_name, 'Local Auto-Generated PKI')

    def test_db_field_name(self):
        """Test that AutoGenPkiFeature has correct db_field_name."""
        self.assertEqual(AutoGenPkiFeature.db_field_name, 'auto_gen_pki')

    def test_is_enabled_returns_false_when_disabled(self):
        """Test is_enabled returns False when auto_gen_pki is False."""
        self.security_config.auto_gen_pki = False
        self.security_config.save()

        self.assertFalse(AutoGenPkiFeature.is_enabled())

    def test_is_enabled_returns_true_when_enabled(self):
        """Test is_enabled returns True when auto_gen_pki is True."""
        self.security_config.auto_gen_pki = True
        self.security_config.save()

        self.assertTrue(AutoGenPkiFeature.is_enabled())

    def test_is_enabled_returns_false_when_no_config(self):
        """Test is_enabled returns False when no SecurityConfig exists."""
        SecurityConfig.objects.all().delete()
        self.assertFalse(AutoGenPkiFeature.is_enabled())

    @patch('management.security.features.AutoGenPki.enable_auto_gen_pki')
    def test_enable_starts_thread_when_enabled(self, mock_enable):
        """Test enable starts a background thread when auto_gen_pki is True."""
        self.security_config.auto_gen_pki = True
        self.security_config.save()

        AutoGenPkiFeature.enable(key_algorithm=AutoGenPkiKeyAlgorithm.RSA2048)

        # Wait for thread to complete
        for thread in threading.enumerate():
            if thread.name == 'AutoGenPKI-Enable':
                thread.join(timeout=2)
                break

        mock_enable.assert_called_once_with(AutoGenPkiKeyAlgorithm.RSA2048)

    def test_enable_raises_error_without_key_algorithm(self):
        """Test enable raises ValueError when key_algorithm is not provided."""
        self.security_config.auto_gen_pki = True
        self.security_config.save()

        with self.assertRaises(ValueError) as context:
            AutoGenPkiFeature.enable()

        self.assertIn('key_algorithm is required', str(context.exception))

    def test_enable_does_not_start_thread_when_disabled(self):
        """Test enable does not start thread when auto_gen_pki is False."""
        self.security_config.auto_gen_pki = False
        self.security_config.save()

        with patch('management.security.features.AutoGenPki.enable_auto_gen_pki') as mock_enable:
            AutoGenPkiFeature.enable(key_algorithm=AutoGenPkiKeyAlgorithm.RSA2048)

            # Wait a bit to ensure thread doesn't start
            import time

            time.sleep(0.1)

            mock_enable.assert_not_called()

    @patch('management.security.features.AutoGenPki.enable_auto_gen_pki')
    def test_enable_handles_exceptions_in_thread(self, mock_enable):
        """Test enable handles exceptions that occur in the background thread."""
        mock_enable.side_effect = Exception('Test exception')
        self.security_config.auto_gen_pki = True
        self.security_config.save()

        # Should not raise exception even though thread encounters error
        AutoGenPkiFeature.enable(key_algorithm=AutoGenPkiKeyAlgorithm.RSA2048)

        # Wait for thread to complete
        for thread in threading.enumerate():
            if thread.name == 'AutoGenPKI-Enable':
                thread.join(timeout=2)
                break

        mock_enable.assert_called_once()

    @patch('management.security.features.AutoGenPki.enable_auto_gen_pki')
    def test_enable_with_different_key_algorithms(self, mock_enable):
        """Test enable works with different key algorithms."""
        self.security_config.auto_gen_pki = True
        self.security_config.save()

        # Test with RSA4096
        AutoGenPkiFeature.enable(key_algorithm=AutoGenPkiKeyAlgorithm.RSA4096)

        for thread in threading.enumerate():
            if thread.name == 'AutoGenPKI-Enable':
                thread.join(timeout=2)
                break

        mock_enable.assert_called_with(AutoGenPkiKeyAlgorithm.RSA4096)

        mock_enable.reset_mock()

        # Test with SECP256R1
        AutoGenPkiFeature.enable(key_algorithm=AutoGenPkiKeyAlgorithm.SECP256R1)

        for thread in threading.enumerate():
            if thread.name == 'AutoGenPKI-Enable':
                thread.join(timeout=2)
                break

        mock_enable.assert_called_with(AutoGenPkiKeyAlgorithm.SECP256R1)

    @patch('management.security.features.AutoGenPki.disable_auto_gen_pki')
    def test_disable_starts_thread(self, mock_disable):
        """Test disable starts a background thread."""
        AutoGenPkiFeature.disable()

        # Wait for thread to complete
        for thread in threading.enumerate():
            if thread.name == 'AutoGenPKI-Disable':
                thread.join(timeout=2)
                break

        mock_disable.assert_called_once()

    @patch('management.security.features.AutoGenPki.disable_auto_gen_pki')
    def test_disable_updates_security_config(self, mock_disable):
        """Test disable updates SecurityConfig.auto_gen_pki to False."""
        self.security_config.auto_gen_pki = True
        self.security_config.save()

        AutoGenPkiFeature.disable()

        # Wait for thread to complete
        for thread in threading.enumerate():
            if thread.name == 'AutoGenPKI-Disable':
                thread.join(timeout=2)
                break

        self.security_config.refresh_from_db()
        self.assertFalse(self.security_config.auto_gen_pki)

    @patch('management.security.features.AutoGenPki.disable_auto_gen_pki')
    def test_disable_handles_no_security_config(self, mock_disable):
        """Test disable handles case when no SecurityConfig exists."""
        SecurityConfig.objects.all().delete()

        # Should not raise exception
        AutoGenPkiFeature.disable()

        # Wait for thread to complete
        for thread in threading.enumerate():
            if thread.name == 'AutoGenPKI-Disable':
                thread.join(timeout=2)
                break

        mock_disable.assert_called_once()

    @patch('management.security.features.AutoGenPki.disable_auto_gen_pki')
    def test_disable_handles_exceptions_in_thread(self, mock_disable):
        """Test disable handles exceptions that occur in the background thread."""
        mock_disable.side_effect = Exception('Test exception')

        # Should not raise exception even though thread encounters error
        AutoGenPkiFeature.disable()

        # Wait for thread to complete
        for thread in threading.enumerate():
            if thread.name == 'AutoGenPKI-Disable':
                thread.join(timeout=2)
                break

        mock_disable.assert_called_once()

    @patch('management.security.features.AutoGenPki.disable_auto_gen_pki')
    def test_disable_accepts_kwargs(self, mock_disable):
        """Test disable accepts kwargs (even though they're unused)."""
        # Should not raise exception with kwargs
        AutoGenPkiFeature.disable(some_param='value', another_param=123)

        # Wait for thread to complete
        for thread in threading.enumerate():
            if thread.name == 'AutoGenPKI-Disable':
                thread.join(timeout=2)
                break

        mock_disable.assert_called_once()

    def test_inherits_from_security_feature(self):
        """Test that AutoGenPkiFeature inherits from SecurityFeature."""
        self.assertTrue(issubclass(AutoGenPkiFeature, SecurityFeature))

    def test_implements_all_abstract_methods(self):
        """Test that AutoGenPkiFeature implements all abstract methods."""
        # Should be able to call all abstract methods
        self.assertTrue(callable(AutoGenPkiFeature.enable))
        self.assertTrue(callable(AutoGenPkiFeature.disable))
        self.assertTrue(callable(AutoGenPkiFeature.is_enabled))
