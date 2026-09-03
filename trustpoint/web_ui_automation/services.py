# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Application services for Web UI automation lifecycle management."""

from __future__ import annotations

import copy
from typing import TYPE_CHECKING

from django.core.exceptions import ValidationError
from django.db import transaction
from django.utils import timezone
from django.utils.translation import gettext_lazy as _

from onboarding.enums import OnboardingStatus
from pki.models.credential import PrimaryCredentialCertificate
from web_ui_automation.audit import WebUiAuditOperation, write_audit_entry
from web_ui_automation.models import (
    AutomationOperation,
    JobResult,
    JobStatus,
    WebUiAutomationAssignedProfile,
    WebUiAutomationJob,
)
from web_ui_automation.notifications import create_job_attention_notification
from web_ui_automation.schema import profile_supports_operation

if TYPE_CHECKING:
    from django.contrib.auth.models import AbstractBaseUser

    from pki.models.certificate import CertificateModel


@transaction.atomic
def create_job(
    assignment: WebUiAutomationAssignedProfile,
    operation: str,
    *,
    actor: AbstractBaseUser | None = None,
    candidate_certificate: CertificateModel | None = None,
    is_automatic: bool = False,
) -> WebUiAutomationJob:
    """Create an immutable job snapshot after validating execution preconditions."""
    if not assignment.enabled:
        raise ValidationError(_('The assigned profile is disabled.'))
    if not profile_supports_operation(assignment.workflow_definition.profile, operation):
        raise ValidationError(_('The profile does not define operation %(operation)s.') % {'operation': operation})
    if operation in {AutomationOperation.ONBOARD, AutomationOperation.RENEW} and candidate_certificate is None:
        raise ValidationError(_('A candidate certificate is required for this operation.'))
    if operation == AutomationOperation.RENEW and is_automatic:
        assignment.validate_automatic_renewal_eligibility()

    assignment.workflow_definition.validate_before_execution()
    profile_snapshot = copy.deepcopy(assignment.workflow_definition.profile)
    job = WebUiAutomationJob.objects.create(
        assignment=assignment,
        operation=operation,
        profile_snapshot=profile_snapshot,
        profile_checksum=assignment.workflow_definition.checksum,
        candidate_certificate=candidate_certificate,
        initiated_by=actor,  # type: ignore[misc]
        is_automatic=is_automatic,
    )
    audit_operation = (
        WebUiAuditOperation.ONBOARDING_STARTED
        if operation == AutomationOperation.ONBOARD
        else WebUiAuditOperation.RENEWAL_STARTED
    )
    if operation != AutomationOperation.INVENTORY:
        write_audit_entry(
            audit_operation,
            assignment,
            actor=actor,
            details={'job_id': job.pk, 'profile_checksum': job.profile_checksum},
        )
    return job


@transaction.atomic
def record_job_failure(
    job: WebUiAutomationJob,
    *,
    failed_step_id: str,
    failure_category: str,
    error_message: str,
) -> None:
    """Persist a failed result, notify the user, and disable automatic renewal."""
    job.status = JobStatus.FAILED
    job.result = JobResult.FAILED
    job.failed_step_id = failed_step_id
    job.failure_category = failure_category
    job.error_message = error_message
    job.finished_at = timezone.now()
    job.save(
        update_fields=[
            'status',
            'result',
            'failed_step_id',
            'failure_category',
            'error_message',
            'finished_at',
        ]
    )

    if job.operation == AutomationOperation.RENEW:
        job.assignment.disable_automatic_renewal()
        write_audit_entry(
            WebUiAuditOperation.RENEWAL_FAILED,
            job.assignment,
            details={'job_id': job.pk, 'failed_step_id': failed_step_id},
        )
    elif job.operation == AutomationOperation.ONBOARD:
        job.assignment.onboarding_status = OnboardingStatus.PENDING
        job.assignment.save(update_fields=['onboarding_status', 'updated_at'])
        write_audit_entry(
            WebUiAuditOperation.ONBOARDING_FAILED,
            job.assignment,
            details={'job_id': job.pk, 'failed_step_id': failed_step_id},
        )
    create_job_attention_notification(job)


@transaction.atomic
def record_job_success(
    job: WebUiAutomationJob,
    *,
    result: str,
    verification_status: str,
) -> None:
    """Persist a successful execution and apply automatic results when permitted."""
    if result not in {JobResult.SUCCESSFUL, JobResult.PARTIALLY_SUCCESSFUL}:
        msg = 'A successful job must have a successful or partially successful result.'
        raise ValueError(msg)

    job.result = result
    job.verification_status = verification_status
    job.finished_at = timezone.now()

    requires_confirmation = (
        result == JobResult.PARTIALLY_SUCCESSFUL
        or job.operation == AutomationOperation.ONBOARD
        or (job.operation == AutomationOperation.RENEW and not job.is_automatic)
    )
    job.status = JobStatus.AWAITING_CONFIRMATION if requires_confirmation else JobStatus.COMPLETED
    job.save(update_fields=['result', 'verification_status', 'finished_at', 'status'])

    if result == JobResult.PARTIALLY_SUCCESSFUL:
        if job.operation == AutomationOperation.RENEW:
            job.assignment.disable_automatic_renewal()
        job.error_message = str(_('One or more verification postconditions did not pass.'))
        job.save(update_fields=['error_message'])
        create_job_attention_notification(job)
    elif job.operation == AutomationOperation.RENEW and job.is_automatic:
        _activate_candidate_certificate(job)
        _mark_assignment_certificate_updated(job.assignment, job.profile_checksum)


@transaction.atomic
def confirm_job(job: WebUiAutomationJob, *, actor: AbstractBaseUser | None = None) -> None:
    """Apply explicit user confirmation for onboarding or a manual renewal."""
    if job.status != JobStatus.AWAITING_CONFIRMATION:
        raise ValidationError(_('This job is not awaiting confirmation.'))
    if job.result not in {JobResult.SUCCESSFUL, JobResult.PARTIALLY_SUCCESSFUL}:
        raise ValidationError(_('Only a successful execution can be confirmed.'))

    assignment = job.assignment
    if job.operation == AutomationOperation.ONBOARD:
        _activate_candidate_certificate(job)
        assignment.onboarding_status = OnboardingStatus.ONBOARDED
        _mark_assignment_certificate_updated(assignment, job.profile_checksum, save=False)
        assignment.save(
            update_fields=[
                'onboarding_status',
                'last_certificate_update',
                'next_certificate_update_scheduled',
                'confirmed_profile_checksum',
                'updated_at',
            ]
        )
        write_audit_entry(
            WebUiAuditOperation.ONBOARDING_CONFIRMED,
            assignment,
            actor=actor,
            details={'job_id': job.pk},
        )
    elif job.operation == AutomationOperation.RENEW:
        _activate_candidate_certificate(job)
        _mark_assignment_certificate_updated(assignment, job.profile_checksum)
        write_audit_entry(
            WebUiAuditOperation.RENEWAL_CONFIRMED,
            assignment,
            actor=actor,
            details={'job_id': job.pk},
        )
    else:
        raise ValidationError(_('Inventory jobs do not require confirmation.'))

    job.status = JobStatus.COMPLETED
    job.save(update_fields=['status'])


@transaction.atomic
def enable_automatic_renewal(
    assignment: WebUiAutomationAssignedProfile,
    *,
    actor: AbstractBaseUser | None = None,
) -> None:
    """Explicitly enable automatic renewal after validating eligibility."""
    assignment.validate_automatic_renewal_eligibility()
    assignment.automatic_renewal_enabled = True
    assignment.save(update_fields=['automatic_renewal_enabled', 'updated_at'])
    write_audit_entry(WebUiAuditOperation.RENEWAL_ENABLED, assignment, actor=actor)


@transaction.atomic
def disable_automatic_renewal(
    assignment: WebUiAutomationAssignedProfile,
    *,
    actor: AbstractBaseUser | None = None,
    reason: str = '',
) -> None:
    """Explicitly disable automatic renewal and write an audit entry."""
    assignment.disable_automatic_renewal()
    write_audit_entry(
        WebUiAuditOperation.RENEWAL_DISABLED,
        assignment,
        actor=actor,
        details={'reason': reason},
    )


def _activate_candidate_certificate(job: WebUiAutomationJob) -> None:
    """Make the job candidate certificate primary on the stable credential model."""
    if job.candidate_certificate is None or job.assignment.issued_credential is None:
        raise ValidationError(_('The job has no candidate certificate or issued credential.'))

    credential = job.assignment.issued_credential.credential
    relationship, _created = PrimaryCredentialCertificate.objects.get_or_create(
        credential=credential,
        certificate=job.candidate_certificate,
        defaults={'is_primary': True},
    )
    if not relationship.is_primary:
        relationship.is_primary = True
        relationship.save(update_fields=['is_primary'])
    credential.certificate = job.candidate_certificate
    credential.save(update_fields=['certificate'])


def _mark_assignment_certificate_updated(
    assignment: WebUiAutomationAssignedProfile,
    profile_checksum: str,
    *,
    save: bool = True,
) -> None:
    """Update renewal timestamps and confirmed checksum after a successful operation."""
    assignment.last_certificate_update = timezone.now()
    assignment.next_certificate_update_scheduled = None
    assignment.confirmed_profile_checksum = profile_checksum
    if save:
        assignment.save(
            update_fields=[
                'last_certificate_update',
                'next_certificate_update_scheduled',
                'confirmed_profile_checksum',
                'updated_at',
            ]
        )
