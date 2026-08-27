# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Apply setup in a detached process while publishing user-visible progress."""

from __future__ import annotations

import logging
import os
from typing import Any

from django.core.exceptions import ValidationError as DjangoValidationError
from django.core.management.base import BaseCommand, CommandError

from setup_wizard.models import SetupWizardConfigModel
from setup_wizard.operational_handoff import (
    refresh_pending_operational_env,
    run_operational_handoff,
    run_operational_runtime_switch,
)
from setup_wizard.setup_apply_progress import APPLY_JOB_ID_ENV, report_setup_apply_progress
from setup_wizard.views import (
    probe_staged_pkcs11_config_isolated,
    validate_staged_pkcs11_app_secret_protection_if_required,
)

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    """Run the bootstrap-to-operational handoff outside the web request."""

    help = 'Apply the staged setup-wizard configuration and publish progress.'

    def handle(self, *_args: Any, **_options: Any) -> None:
        """Apply staged configuration, switch runtimes, and record failures."""
        job_id = os.getenv(APPLY_JOB_ID_ENV)
        if not job_id:
            msg = 'This command must be started by the setup wizard progress service.'
            raise CommandError(msg)

        try:
            self._apply()
        except Exception as exception:
            logger.exception('Background setup-wizard apply failed.')
            detail = self._error_detail(exception)
            report_setup_apply_progress('failed', detail, 100, state='failed')
            raise CommandError(detail) from exception

    @staticmethod
    def _error_detail(exception: Exception) -> str:
        """Return a bounded, user-facing error without exposing command internals."""
        detail = '; '.join(exception.messages) if isinstance(exception, DjangoValidationError) else str(exception)
        return (detail or 'Setup failed. Check the Trustpoint log for details.')[-4000:]

    @staticmethod
    def _apply() -> None:
        """Perform the same validated handoff previously run inside the request."""
        report_setup_apply_progress('starting', 'Starting setup validation.', 2)
        config_model = SetupWizardConfigModel.get_singleton()

        if config_model.operational_config_applied:
            report_setup_apply_progress('runtime', 'Retrying the operational runtime switch.', 90)
            result = refresh_pending_operational_env(config_model)
        else:
            if config_model.crypto_storage == SetupWizardConfigModel.CryptoStorageType.HsmStorage:
                report_setup_apply_progress('hsm-validation', 'Validating the configured HSM.', 5)
                probe_staged_pkcs11_config_isolated(
                    config_model,
                    profile_name='setup-wizard-pkcs11-pre-apply',
                )
                validate_staged_pkcs11_app_secret_protection_if_required(
                    config_model,
                    profile_name='setup-wizard-pkcs11-pre-apply-app-secret',
                )

            report_setup_apply_progress('database', 'Preparing the operational database.', 12)
            result = run_operational_handoff(config_model)
            config_model.mark_step_submitted(SetupWizardConfigModel.FreshInstallCurrentStep.SUMMARY)
            config_model.operational_config_applied = True
            config_model.save(update_fields=['fresh_install_summary_submitted', 'operational_config_applied'])

        report_setup_apply_progress('runtime', 'Starting the operational Trustpoint services.', 92, state='switching')
        run_operational_runtime_switch(result.pending_env_file)
        report_setup_apply_progress('complete', 'Trustpoint setup completed successfully.', 100, state='complete')
