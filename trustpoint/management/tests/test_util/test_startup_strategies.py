"""Tests for the explicit bootstrap and operational startup helpers."""

from unittest.mock import Mock

from django.test import TestCase
from packaging.version import Version

from management.util.startup_strategies import (
    CompletedRuntimeStartupStrategy,
    StartupContext,
    WizardState,
)


class WizardStateTest(TestCase):
    """Test suite for WizardState enum."""

    def test_completed_value(self) -> None:
        """Test COMPLETED enum value."""
        self.assertEqual(WizardState.COMPLETED.value, 'COMPLETED')

    def test_incomplete_value(self) -> None:
        """Test INCOMPLETE enum value."""
        self.assertEqual(WizardState.INCOMPLETE.value, 'INCOMPLETE')


class StartupContextTest(TestCase):
    """Test suite for the reduced startup context."""

    def test_is_wizard_completed_true(self) -> None:
        """Test is_wizard_completed property when completed."""
        context = StartupContext(
            current_version=Version('1.0.0'),
            db_version=Version('1.0.0'),
            wizard_state_enum=WizardState.COMPLETED,
            wizard_current_step=None,
            backend_kind=None,
            appsecrets_configured=False,
            has_staged_tls=False,
            output=Mock(),
        )

        self.assertTrue(context.is_wizard_completed)

    def test_is_wizard_completed_false(self) -> None:
        """Test is_wizard_completed property when incomplete."""
        context = StartupContext(
            current_version=Version('1.0.0'),
            db_version=None,
            wizard_state_enum=WizardState.INCOMPLETE,
            wizard_current_step=None,
            backend_kind=None,
            appsecrets_configured=False,
            has_staged_tls=True,
            output=Mock(),
        )

        self.assertFalse(context.is_wizard_completed)


class CompletedRuntimeStartupStrategyTest(TestCase):
    """Test suite for the operational startup path."""

    def test_description_is_operational_only(self) -> None:
        """Test the operational path description."""
        strategy = CompletedRuntimeStartupStrategy(tls_strategy=Mock(), runtime_initialization=Mock())

        self.assertEqual(strategy.get_description(), 'Completed runtime startup (setup wizard completed)')

    def test_execute_requires_appsecrets_before_runtime_initialization(self) -> None:
        """Test execute runs readiness checks before TLS and runtime initialization."""
        tls_strategy = Mock()
        runtime_initialization = Mock()
        strategy = CompletedRuntimeStartupStrategy(
            tls_strategy=tls_strategy,
            runtime_initialization=runtime_initialization,
        )
        context = Mock()

        strategy._ensure_appsecrets_ready = Mock()
        strategy.execute(context)

        strategy._ensure_appsecrets_ready.assert_called_once_with(context)
        tls_strategy.apply.assert_called_once_with(context)
        runtime_initialization.initialize.assert_called_once_with(context)
