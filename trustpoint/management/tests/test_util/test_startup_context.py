"""Tests for the operational startup context builder."""

from unittest.mock import Mock, patch

from django.test import TestCase
from packaging.version import Version

from management.util.startup_context import StartupContextBuilder
from management.util.startup_strategies import WizardState


class StartupContextBuilderTest(TestCase):
    """Test suite for StartupContextBuilder."""

    def setUp(self) -> None:
        """Set up test fixtures."""
        self.mock_output = Mock()
        self.current_version = Version('1.0.0')
        self.builder = StartupContextBuilder(self.mock_output, self.current_version)

    def test_init(self) -> None:
        """Test initialization sets default values."""
        self.assertEqual(self.builder.output, self.mock_output)
        self.assertEqual(self.builder.current_version, self.current_version)
        self.assertIsNone(self.builder.db_version)
        self.assertIsNone(self.builder.backend_kind)
        self.assertFalse(self.builder.appsecrets_configured)
        self.assertFalse(self.builder.has_staged_tls)

    def test_with_db_version(self) -> None:
        """Test setting database version."""
        db_version = Version('0.9.0')

        result = self.builder.with_db_version(db_version)

        self.assertEqual(self.builder.db_version, db_version)
        self.assertEqual(result, self.builder)

    @patch('management.util.startup_context.configured_backend_kind')
    def test_collect_backend_state(self, mock_configured_backend_kind: Mock) -> None:
        """Test collecting configured backend kind."""
        mock_configured_backend_kind.return_value = None

        result = self.builder.collect_backend_state()

        self.assertIsNone(self.builder.backend_kind)
        self.assertEqual(result, self.builder)

    @patch('management.util.startup_context.load_staged_tls_credential')
    def test_collect_tls_staging_state(self, mock_load_staged_tls_credential: Mock) -> None:
        """Test collecting staged TLS state."""
        mock_load_staged_tls_credential.return_value = object()

        result = self.builder.collect_tls_staging_state()

        self.assertTrue(self.builder.has_staged_tls)
        self.assertEqual(result, self.builder)

    def test_build(self) -> None:
        """Test building the reduced startup context."""
        db_version = Version('0.9.0')
        self.builder.with_db_version(db_version)

        context = self.builder.build()

        self.assertEqual(context.current_version, self.current_version)
        self.assertEqual(context.db_version, db_version)
        self.assertEqual(context.wizard_state_enum, WizardState.COMPLETED)
        self.assertIsNone(context.wizard_current_step)
        self.assertIsNone(context.backend_kind)
        self.assertFalse(context.appsecrets_configured)
        self.assertFalse(context.has_staged_tls)
        self.assertEqual(context.output, self.mock_output)
