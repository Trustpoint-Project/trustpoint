"""Tests for utility functions in setup_wizard views."""

import subprocess
from pathlib import Path
from unittest.mock import Mock, patch

import pytest
from django.test import TestCase

from setup_wizard.views import (
    TrustpointTlsServerCredentialError,
    TrustpointWizardError,
    execute_shell_script,
)


class TrustpointWizardErrorTests(TestCase):
    """Test cases for TrustpointWizardError exception."""

    def test_exception_can_be_raised(self) -> None:
        """Test that TrustpointWizardError can be raised."""
        with self.assertRaises(TrustpointWizardError):
            raise TrustpointWizardError()

    def test_exception_with_custom_message(self) -> None:
        """Test TrustpointWizardError with custom message."""
        custom_message = "Custom wizard error"
        with self.assertRaises(TrustpointWizardError) as cm:
            raise TrustpointWizardError(custom_message)
        
        assert str(cm.exception) == custom_message


class TrustpointTlsServerCredentialErrorTests(TestCase):
    """Test cases for TrustpointTlsServerCredentialError exception."""

    def test_exception_default_message(self) -> None:
        """Test default error message."""
        with self.assertRaises(TrustpointTlsServerCredentialError) as cm:
            raise TrustpointTlsServerCredentialError()
        
        assert 'Trustpoint TLS Server Credential error occurred' in str(cm.exception)

    def test_exception_custom_message(self) -> None:
        """Test custom error message."""
        custom_message = "Missing TLS credentials"
        with self.assertRaises(TrustpointTlsServerCredentialError) as cm:
            raise TrustpointTlsServerCredentialError(custom_message)
        
        assert str(cm.exception) == custom_message


class ExecuteShellScriptTests(TestCase):
    """Test cases for execute_shell_script function."""

    @patch('setup_wizard.views.subprocess.run')
    def test_execute_script_success(self, mock_run: Mock) -> None:
        """Test successful script execution."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_run.return_value = mock_result

        with patch('setup_wizard.views.Path.exists', return_value=True), \
             patch('setup_wizard.views.Path.is_file', return_value=True):
            
            script_path = Path('/tmp/test_script.sh')
            execute_shell_script(script_path)
            
            mock_run.assert_called_once()
            call_args = mock_run.call_args[0][0]
            assert call_args[0] == 'sudo'
            assert 'test_script.sh' in call_args[1]

    @patch('setup_wizard.views.subprocess.run')
    def test_execute_script_with_arguments(self, mock_run: Mock) -> None:
        """Test script execution with arguments."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_run.return_value = mock_result

        with patch('setup_wizard.views.Path.exists', return_value=True), \
             patch('setup_wizard.views.Path.is_file', return_value=True):
            
            script_path = Path('/tmp/test_script.sh')
            execute_shell_script(script_path, 'arg1', 'arg2', 'arg3')
            
            mock_run.assert_called_once()
            call_args = mock_run.call_args[0][0]
            assert 'arg1' in call_args
            assert 'arg2' in call_args
            assert 'arg3' in call_args

    def test_execute_script_not_found(self) -> None:
        """Test error when script doesn't exist."""
        with patch('setup_wizard.views.Path.exists', return_value=False):
            script_path = Path('/nonexistent/script.sh')
            
            with self.assertRaises(FileNotFoundError) as cm:
                execute_shell_script(script_path)
            
            assert 'State bump script not found' in str(cm.exception)

    def test_execute_script_not_a_file(self) -> None:
        """Test error when path is not a file."""
        with patch('setup_wizard.views.Path.exists', return_value=True), \
             patch('setup_wizard.views.Path.is_file', return_value=False):
            
            script_path = Path('/tmp/directory')
            
            with self.assertRaises(ValueError) as cm:
                execute_shell_script(script_path)
            
            assert 'not a valid file' in str(cm.exception)

    @patch('setup_wizard.views.subprocess.run')
    def test_execute_script_failure(self, mock_run: Mock) -> None:
        """Test handling of script execution failure."""
        mock_result = Mock()
        mock_result.returncode = 1
        mock_run.return_value = mock_result

        with patch('setup_wizard.views.Path.exists', return_value=True), \
             patch('setup_wizard.views.Path.is_file', return_value=True):
            
            script_path = Path('/tmp/failing_script.sh')
            
            with self.assertRaises(subprocess.CalledProcessError):
                execute_shell_script(script_path)
