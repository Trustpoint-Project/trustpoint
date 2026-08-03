# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Django-Q2 tasks for Web UI automation execution and maintenance."""

from __future__ import annotations

import asyncio
import concurrent.futures

from django import db
from django.core.exceptions import ImproperlyConfigured, ValidationError

from onboarding.enums import OnboardingStatus
from web_ui_automation.executor import execute_job
from web_ui_automation.models import JobStatus, WebUiAutomationAssignedProfile
from web_ui_automation.orchestration import queue_operation


def _execute_job_in_thread(job_id: int) -> None:
    """Execute a job in a thread-safe manner with proper database connection handling."""
    db.connections.close_all()
    try:
        execute_job(job_id)
    finally:
        db.connections.close_all()


def execute_web_ui_automation_job(job_id: int) -> None:
    """Django-Q2 entry point for executing one queued automation job.

    This function ensures synchronous execution even when called from an async context.
    """
    try:
        asyncio.get_running_loop()
        with concurrent.futures.ThreadPoolExecutor() as executor:
            future = executor.submit(_execute_job_in_thread, job_id)
            return future.result()
    except RuntimeError:
        execute_job(job_id)

def enqueue_due_renewals() -> int:
    """Queue all eligible automatic renewals that are currently due."""
    queued = 0
    assignments = WebUiAutomationAssignedProfile.objects.filter(
        enabled=True,
        automatic_renewal_enabled=True,
        onboarding_status=OnboardingStatus.ONBOARDED,
    ).select_related('workflow_definition', 'issued_credential__credential__certificate')
    for assignment in assignments:
        if not assignment.is_due_for_renewal:
            continue
        active_job_exists = assignment.jobs.filter(
            operation='renew',
            status__in=[JobStatus.QUEUED, JobStatus.RUNNING],
        ).exists()
        if active_job_exists:
            continue
        try:
            queue_operation(assignment, 'renew', is_automatic=True)
        except (ImproperlyConfigured, ValidationError, ValueError):
            assignment.disable_automatic_renewal()
            continue
        queued += 1
    return queued
