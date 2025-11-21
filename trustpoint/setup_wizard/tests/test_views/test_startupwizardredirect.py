"""Tests for the StartupWizardRedirect class."""

from unittest.mock import Mock, patch

import pytest
from django.http import HttpResponseRedirect
from django.test import TestCase
from django.urls import reverse
from management.models import KeyStorageConfig

from setup_wizard import SetupWizardState
from setup_wizard.views import StartupWizardRedirect


class StartupWizardRedirectTestCase(TestCase):
    """Test cases for StartupWizardRedirect class."""

    def test_redirect_by_state_crypto_storage(self):
        """Test redirect for WIZARD_SETUP_CRYPTO_STORAGE state."""
        result = StartupWizardRedirect.redirect_by_state(SetupWizardState.WIZARD_SETUP_CRYPTO_STORAGE)

        self.assertIsInstance(result, HttpResponseRedirect)
        expected_url = reverse('setup_wizard:crypto_storage_setup')
        self.assertEqual(result.url, expected_url)

    def test_redirect_by_state_setup_mode(self):
        """Test redirect for WIZARD_SETUP_MODE state."""
        result = StartupWizardRedirect.redirect_by_state(SetupWizardState.WIZARD_SETUP_MODE)

        self.assertIsInstance(result, HttpResponseRedirect)
        expected_url = reverse('setup_wizard:setup_mode')
        self.assertEqual(result.url, expected_url)

    def test_redirect_by_state_tls_server_credential_apply(self):
        """Test redirect for WIZARD_TLS_SERVER_CREDENTIAL_APPLY state."""
        result = StartupWizardRedirect.redirect_by_state(SetupWizardState.WIZARD_TLS_SERVER_CREDENTIAL_APPLY)

        self.assertIsInstance(result, HttpResponseRedirect)
        expected_url = reverse('setup_wizard:tls_server_credential_apply')
        self.assertEqual(result.url, expected_url)

    def test_redirect_by_state_backup_password(self):
        """Test redirect for WIZARD_BACKUP_PASSWORD state."""
        result = StartupWizardRedirect.redirect_by_state(SetupWizardState.WIZARD_BACKUP_PASSWORD)

        self.assertIsInstance(result, HttpResponseRedirect)
        expected_url = reverse('setup_wizard:backup_password')
        self.assertEqual(result.url, expected_url)

    def test_redirect_by_state_demo_data(self):
        """Test redirect for WIZARD_DEMO_DATA state."""
        result = StartupWizardRedirect.redirect_by_state(SetupWizardState.WIZARD_DEMO_DATA)

        self.assertIsInstance(result, HttpResponseRedirect)
        expected_url = reverse('setup_wizard:demo_data')
        self.assertEqual(result.url, expected_url)

    def test_redirect_by_state_create_super_user(self):
        """Test redirect for WIZARD_CREATE_SUPER_USER state."""
        result = StartupWizardRedirect.redirect_by_state(SetupWizardState.WIZARD_CREATE_SUPER_USER)

        self.assertIsInstance(result, HttpResponseRedirect)
        expected_url = reverse('setup_wizard:create_super_user')
        self.assertEqual(result.url, expected_url)

    def test_redirect_by_state_completed(self):
        """Test redirect for WIZARD_COMPLETED state."""
        result = StartupWizardRedirect.redirect_by_state(SetupWizardState.WIZARD_COMPLETED)

        self.assertIsInstance(result, HttpResponseRedirect)
        expected_url = reverse('users:login')
        self.assertEqual(result.url, expected_url)

    def test_redirect_by_state_auto_restore_password(self):
        """Test redirect for WIZARD_AUTO_RESTORE_PASSWORD state."""
        result = StartupWizardRedirect.redirect_by_state(SetupWizardState.WIZARD_AUTO_RESTORE_PASSWORD)

        self.assertIsInstance(result, HttpResponseRedirect)
        expected_url = reverse('setup_wizard:auto_restore_password')
        self.assertEqual(result.url, expected_url)

    @pytest.mark.django_db
    def test_redirect_by_state_setup_hsm_softhsm(self):
        """Test redirect for WIZARD_SETUP_HSM state with SoftHSM storage type."""
        # Mock KeyStorageConfig.get_config() to return a config with SOFTHSM
        mock_config = Mock()
        mock_config.storage_type = KeyStorageConfig.StorageType.SOFTHSM

        with patch.object(KeyStorageConfig, 'get_config', return_value=mock_config):
            result = StartupWizardRedirect.redirect_by_state(SetupWizardState.WIZARD_SETUP_HSM)

        self.assertIsInstance(result, HttpResponseRedirect)
        expected_url = reverse('setup_wizard:hsm_setup', kwargs={'hsm_type': 'softhsm'})
        self.assertEqual(result.url, expected_url)

    @pytest.mark.django_db
    def test_redirect_by_state_setup_hsm_physical(self):
        """Test redirect for WIZARD_SETUP_HSM state with Physical HSM storage type."""
        # Mock KeyStorageConfig.get_config() to return a config with PHYSICAL_HSM
        mock_config = Mock()
        mock_config.storage_type = KeyStorageConfig.StorageType.PHYSICAL_HSM

        with patch.object(KeyStorageConfig, 'get_config', return_value=mock_config):
            result = StartupWizardRedirect.redirect_by_state(SetupWizardState.WIZARD_SETUP_HSM)

        self.assertIsInstance(result, HttpResponseRedirect)
        expected_url = reverse('setup_wizard:hsm_setup', kwargs={'hsm_type': 'physical'})
        self.assertEqual(result.url, expected_url)

    @pytest.mark.django_db
    def test_redirect_by_state_setup_hsm_invalid_storage_type(self):
        """Test redirect for WIZARD_SETUP_HSM state with invalid storage type."""
        # Mock KeyStorageConfig.get_config() to return a config with SOFTWARE storage type
        mock_config = Mock()
        mock_config.storage_type = KeyStorageConfig.StorageType.SOFTWARE

        with patch.object(KeyStorageConfig, 'get_config', return_value=mock_config):
            with self.assertRaises(ValueError) as context:
                StartupWizardRedirect.redirect_by_state(SetupWizardState.WIZARD_SETUP_HSM)

            self.assertEqual(str(context.exception), 'Invalid storage type for HSM setup.')

    def test_redirect_by_state_setup_hsm_no_config(self):
        """Test redirect for WIZARD_SETUP_HSM state when KeyStorageConfig doesn't exist."""
        # Mock KeyStorageConfig.get_config() to raise DoesNotExist
        with patch.object(KeyStorageConfig, 'get_config', side_effect=KeyStorageConfig.DoesNotExist):
            with self.assertRaises(ValueError) as context:
                StartupWizardRedirect.redirect_by_state(SetupWizardState.WIZARD_SETUP_HSM)

            self.assertEqual(str(context.exception), 'KeyStorageConfig is not configured.')

    def test_redirect_by_state_unknown_state(self):
        """Test redirect for an unknown wizard state."""
        # Test with a None value to simulate an invalid state
        with self.assertRaises(ValueError) as context:
            StartupWizardRedirect.redirect_by_state(None)

        self.assertEqual(str(context.exception), 'Unknown wizard state found. Failed to redirect by state.')

    def test_redirect_by_state_returns_redirect_response(self):
        """Test that redirect returns HttpResponseRedirect."""
        result = StartupWizardRedirect.redirect_by_state(SetupWizardState.WIZARD_SETUP_CRYPTO_STORAGE)

        # Check that it's an HttpResponseRedirect
        self.assertIsInstance(result, HttpResponseRedirect)
        # Check that it has a status code of 302 (temporary redirect)
        self.assertEqual(result.status_code, 302)

    @pytest.mark.django_db
    def test_redirect_by_state_hsm_returns_redirect_response(self):
        """Test that HSM redirect returns HttpResponseRedirect."""
        # Mock KeyStorageConfig.get_config() to return a config with SOFTHSM
        mock_config = Mock()
        mock_config.storage_type = KeyStorageConfig.StorageType.SOFTHSM

        with patch.object(KeyStorageConfig, 'get_config', return_value=mock_config):
            result = StartupWizardRedirect.redirect_by_state(SetupWizardState.WIZARD_SETUP_HSM)

        # Check that it's an HttpResponseRedirect
        self.assertIsInstance(result, HttpResponseRedirect)
        # Check that it has a status code of 302 (temporary redirect)
        self.assertEqual(result.status_code, 302)

    def test_all_standard_states_covered(self):
        """Test that all standard wizard states (except HSM) have URL mappings."""
        standard_states = [
            SetupWizardState.WIZARD_SETUP_CRYPTO_STORAGE,
            SetupWizardState.WIZARD_SETUP_MODE,
            SetupWizardState.WIZARD_TLS_SERVER_CREDENTIAL_APPLY,
            SetupWizardState.WIZARD_BACKUP_PASSWORD,
            SetupWizardState.WIZARD_DEMO_DATA,
            SetupWizardState.WIZARD_CREATE_SUPER_USER,
            SetupWizardState.WIZARD_COMPLETED,
        ]

        for state in standard_states:
            with self.subTest(state=state):
                result = StartupWizardRedirect.redirect_by_state(state)
                self.assertIsInstance(result, HttpResponseRedirect)
                self.assertEqual(result.status_code, 302)

    @pytest.mark.django_db
    def test_hsm_state_with_both_storage_types(self):
        """Test HSM state behavior with both valid storage types."""
        storage_types = [
            (KeyStorageConfig.StorageType.SOFTHSM, 'softhsm'),
            (KeyStorageConfig.StorageType.PHYSICAL_HSM, 'physical'),
        ]

        for storage_type, expected_hsm_type in storage_types:
            with self.subTest(storage_type=storage_type):
                mock_config = Mock()
                mock_config.storage_type = storage_type

                with patch.object(KeyStorageConfig, 'get_config', return_value=mock_config):
                    result = StartupWizardRedirect.redirect_by_state(SetupWizardState.WIZARD_SETUP_HSM)

                self.assertIsInstance(result, HttpResponseRedirect)
                expected_url = reverse('setup_wizard:hsm_setup', kwargs={'hsm_type': expected_hsm_type})
                self.assertEqual(result.url, expected_url)

    def test_method_is_static(self):
        """Test that redirect_by_state is a static method."""
        # This test ensures the method can be called without instantiating the class
        self.assertTrue(callable(StartupWizardRedirect.redirect_by_state))

        # Test calling it directly on the class
        result = StartupWizardRedirect.redirect_by_state(SetupWizardState.WIZARD_SETUP_CRYPTO_STORAGE)
        self.assertIsInstance(result, HttpResponseRedirect)
