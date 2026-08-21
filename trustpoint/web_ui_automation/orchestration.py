# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Orchestrate issuance, job snapshots, and Django-Q2 execution."""

from __future__ import annotations

from typing import TYPE_CHECKING

from django.db import transaction
from django_q.tasks import async_task  # type: ignore[import-untyped]

from web_ui_automation.issuance import get_issuance_adapter
from web_ui_automation.models import AutomationOperation, WebUiAutomationAssignedProfile, WebUiAutomationJob
from web_ui_automation.services import create_job

if TYPE_CHECKING:
    from django.contrib.auth.models import AbstractBaseUser


@transaction.atomic
def queue_operation(
    assignment: WebUiAutomationAssignedProfile,
    operation: str,
    *,
    actor: AbstractBaseUser | None = None,
    is_automatic: bool = False,
) -> WebUiAutomationJob:
    """Prepare certificate material, create a job snapshot, and enqueue execution."""
    candidate_certificate = None
    if operation in {AutomationOperation.ONBOARD, AutomationOperation.RENEW}:
        adapter = get_issuance_adapter()
        prepared = (
            adapter.prepare_onboarding(assignment)
            if operation == AutomationOperation.ONBOARD
            else adapter.prepare_renewal(assignment)
        )
        if assignment.issued_credential_id != prepared.issued_credential.pk:
            assignment.issued_credential = prepared.issued_credential
            assignment.save(update_fields=['issued_credential', 'updated_at'])
        candidate_certificate = prepared.candidate_certificate

    job = create_job(
        assignment,
        operation,
        actor=actor,
        candidate_certificate=candidate_certificate,
        is_automatic=is_automatic,
    )

    transaction.on_commit(lambda: async_task('web_ui_automation.tasks.execute_web_ui_automation_job', job.pk))

    return job
