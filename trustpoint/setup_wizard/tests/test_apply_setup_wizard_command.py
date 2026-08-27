# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Tests for the detached setup-wizard apply command."""

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from django.core.management.base import CommandError

from setup_wizard.management.commands.apply_setup_wizard import Command
from setup_wizard.models import SetupWizardConfigModel
from setup_wizard.operational_handoff import OperationalHandoffResult


def _handoff_result(tmp_path: Path) -> OperationalHandoffResult:
    """Create paths returned by the operational handoff service."""
    return OperationalHandoffResult(
        env_file=tmp_path / 'operational.env',
        pending_env_file=tmp_path / 'operational.env.pending',
        ready_file=tmp_path / 'operational.ready',
        payload_file=tmp_path / 'bootstrap-apply.json',
    )


def test_apply_runs_hsm_validation_handoff_and_runtime_switch(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """The worker owns the complete validated bootstrap handoff."""
    monkeypatch.setenv('TRUSTPOINT_SETUP_APPLY_JOB_ID', 'job-1')
    config = MagicMock(
        crypto_storage=SetupWizardConfigModel.CryptoStorageType.HsmStorage,
        operational_config_applied=False,
    )
    result = _handoff_result(tmp_path)

    with (
        patch.object(SetupWizardConfigModel, 'get_singleton', return_value=config),
        patch('setup_wizard.management.commands.apply_setup_wizard.probe_staged_pkcs11_config_isolated') as probe,
        patch(
            'setup_wizard.management.commands.apply_setup_wizard.'
            'validate_staged_pkcs11_app_secret_protection_if_required'
        ) as validate_app_secrets,
        patch('setup_wizard.management.commands.apply_setup_wizard.run_operational_handoff', return_value=result),
        patch('setup_wizard.management.commands.apply_setup_wizard.run_operational_runtime_switch') as switch,
        patch('setup_wizard.management.commands.apply_setup_wizard.report_setup_apply_progress'),
    ):
        Command().handle()

    probe.assert_called_once_with(config, profile_name='setup-wizard-pkcs11-pre-apply')
    validate_app_secrets.assert_called_once_with(
        config,
        profile_name='setup-wizard-pkcs11-pre-apply-app-secret',
    )
    config.mark_step_submitted.assert_called_once_with(SetupWizardConfigModel.FreshInstallCurrentStep.SUMMARY)
    switch.assert_called_once_with(result.pending_env_file)


def test_handle_records_terminal_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    """An apply exception becomes a failed status before the command exits."""
    monkeypatch.setenv('TRUSTPOINT_SETUP_APPLY_JOB_ID', 'job-1')

    with (
        patch.object(Command, '_apply', side_effect=RuntimeError('apply failed')),
        patch('setup_wizard.management.commands.apply_setup_wizard.report_setup_apply_progress') as report,
        pytest.raises(CommandError, match='apply failed'),
    ):
        Command().handle()

    report.assert_called_once_with('failed', 'apply failed', 100, state='failed')
