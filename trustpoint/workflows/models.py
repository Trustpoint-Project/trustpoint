"""Workflow models: definitions, scopes, instances, and enrollment requests."""

from __future__ import annotations

import uuid
from typing import Any, cast

from django.db import models
from django.db.models import JSONField

# -------------------------------
# Workflow definitions + scoping
# -------------------------------


class WorkflowDefinition(models.Model):
    """Blueprint of a workflow: event, steps, transitions."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=100, unique=True)
    version = models.PositiveIntegerField(default=1)
    published = models.BooleanField(default=False)
    definition = JSONField()  # {"event":[...], "steps":[...]}
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'workflow_definitions'
        ordering = ('-created_at',)

    def __str__(self) -> str:  # DJ008
        return f'{self.name} v{self.version}'


class WorkflowScope(models.Model):
    """Assign a workflow to CAs, domains, or devices (NULL = any)."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    workflow = models.ForeignKey(WorkflowDefinition, on_delete=models.CASCADE, related_name='scopes')
    ca_id = models.IntegerField(null=True, blank=True)
    domain_id = models.IntegerField(null=True, blank=True)
    device_id = models.IntegerField(null=True, blank=True)

    class Meta:
        db_table = 'workflow_scopes'
        unique_together = (('workflow', 'ca_id', 'domain_id', 'device_id'),)

    def __str__(self) -> str:  # DJ008
        parts: list[str] = []
        if self.ca_id is not None:
            parts.append(f'CA={self.ca_id}')
        if self.domain_id is not None:
            parts.append(f'Domain={self.domain_id}')
        if self.device_id is not None:
            parts.append(f'Device={self.device_id}')
        suffix = ', '.join(parts) if parts else 'any'
        return f'{self.workflow.name} [{suffix}]'


# -------------------------------------
# EnrollmentRequest (EST fan-out parent)
# -------------------------------------


class EnrollmentRequest(models.Model):
    """A single logical certificate enrollment attempt (EST simpleenroll fan-out parent).

    - Aggregates all child WorkflowInstances that must approve/reject this attempt.
    - Identity tuple groups repeated polls for the same CSR until a terminal outcome.
    - We keep request-level states distinct from instance-level strings to avoid confusion.
    """

    # Request-level aggregate states
    STATE_PENDING = 'Pending'  # at least one child is Starting/Running/AwaitingApproval OR no children yet
    STATE_APPROVED = 'Approved'  # all children are Approved
    STATE_PASSED = 'Passed'
    STATE_REJECTED = 'Rejected'  # any child rejected
    STATE_FAILED = 'Failed'  # any child failed (and none rejected)
    STATE_FINALIZED = 'Finalized'  # certificate issued; request finalized
    STATE_NOMATCH = 'NoMatch'

    STATE_CHOICES = (
        (STATE_PENDING, 'Pending'),
        (STATE_APPROVED, 'Approved'),
        (STATE_PASSED, 'Passed'),
        (STATE_REJECTED, 'Rejected'),
        (STATE_FAILED, 'Failed'),
        (STATE_FINALIZED, 'Finalized'),
        (STATE_NOMATCH, 'NoMatch'),
    )

    TERMINAL_STATES = {STATE_FAILED, STATE_FINALIZED}

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    # Identity tuple (NOT unique → allow a new attempt after terminal)
    protocol = models.CharField(max_length=50)
    operation = models.CharField(max_length=50)
    ca_id = models.IntegerField(null=True, blank=True)
    domain_id = models.IntegerField(null=True, blank=True)
    device_id = models.IntegerField(null=True, blank=True)
    fingerprint = models.CharField(max_length=128)  # CSR fingerprint (sha256 hex)
    template = models.CharField(max_length=100, null=True, blank=True)

    aggregated_state = models.CharField(max_length=32, choices=STATE_CHOICES, default=STATE_PENDING)
    finalized = models.BooleanField(default=False)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'enrollment_requests'
        indexes = (
            # Fast lookup by identity tuple when reusing the "open" request
            models.Index(
                fields=['protocol', 'operation', 'ca_id', 'domain_id', 'device_id', 'fingerprint', 'template']
            ),
            models.Index(fields=['aggregated_state']),
            models.Index(fields=['finalized']),
        )

    def __str__(self) -> str:  # DJ008
        return (
            f'EnrollReq#{self.pk} {self.aggregated_state} {self.protocol}/{self.operation} fp={self.fingerprint[:8]}…'
        )

    # ---- aggregation helpers ----

    def recompute_status(self) -> str:
        """Compute aggregate status from child instances.

        - any Rejected → Rejected
        - else any Failed → Failed
        - else any AwaitingApproval/Running/Starting OR no children → Pending
        - else if all in {Approved, Completed} → Ready
        """
        children = list(self.instances.all())  # via WorkflowInstance.enrollment_request related_name
        if not children:
            return self.STATE_PENDING

        inst_states = {c.state for c in children}

        from .models import WorkflowInstance as WI  # local import to avoid circular typing confusion

        if WI.STATE_REJECTED in inst_states:
            return self.STATE_REJECTED
        if WI.STATE_FAILED in inst_states:
            return self.STATE_FAILED
        if WI.STATE_AWAITING in inst_states or WI.STATE_RUNNING in inst_states:
            return self.STATE_PENDING
        if inst_states.issubset({WI.STATE_APPROVED, WI.STATE_FINALIZED}):
            return self.STATE_APPROVED

        return self.STATE_PENDING

    def is_valid(self) -> bool:
        return self.aggregated_state in {self.STATE_APPROVED, self.STATE_PASSED, self.STATE_NOMATCH}


    def recompute_and_save(self) -> str:
        new_status = self.recompute_status()
        if new_status != self.aggregated_state:
            self.aggregated_state = new_status
            self.save(update_fields=['aggregated_state', 'updated_at'])
        return self.aggregated_state

    def finalize_to(self, final_status: str) -> None:
        """Finalize all non-finalized children."""
        updates = []
        if self.aggregated_state != final_status:
            self.aggregated_state = final_status
            updates.append('aggregated_state')
        if not self.finalized:
            self.finalized = True
            updates.append('finalized')
        if updates:
            self.save(update_fields=updates)

        for inst in self.instances.filter(finalized=False):
            inst.finalize()
            inst.save(update_fields=['finalized'])


# -------------------------------
# Workflow instances (children)
# -------------------------------


class WorkflowInstance(models.Model):
    """An initialized workflows."""

    # possible states
    STATE_RUNNING = 'Running'
    STATE_AWAITING = 'AwaitingApproval'
    STATE_APPROVED = 'Approved'
    STATE_PASSED = 'Passed'
    STATE_FINALIZED = 'Finalized'
    STATE_REJECTED = 'Rejected'
    STATE_FAILED = 'Failed'

    STATE_CHOICES = (
        (STATE_RUNNING, 'Running'),
        (STATE_AWAITING, 'AwaitingApproval'),
        (STATE_APPROVED, 'Approved'),
        (STATE_PASSED, 'Passed'),
        (STATE_FINALIZED, 'Finalized'),
        (STATE_FAILED, 'Failed'),
        (STATE_REJECTED, 'Rejected'),
    )

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    definition = models.ForeignKey(WorkflowDefinition, on_delete=models.CASCADE, related_name='instances')

    # link to parent EnrollmentRequest (EST fan-out)
    enrollment_request = models.ForeignKey(
        EnrollmentRequest,
        null=True,
        blank=True,
        on_delete=models.CASCADE,
        related_name='instances',
        help_text='Parent request for EST fan-out orchestration.',
    )

    current_step = models.CharField(max_length=100, help_text='The step-ID we are currently at (e.g. "step-1")')
    state = models.CharField(max_length=32, choices=STATE_CHOICES, default=STATE_RUNNING)

    payload = JSONField(help_text='Immutable inputs (eg. CSR fingerprint, CA/Domain/Device IDs)')
    step_contexts = JSONField(
        default=dict,
        help_text=('Mutable per-step storage: e.g. for Approval, email-sent flag; for Timer, deadline timestamp; etc.'),
    )
    finalized = models.BooleanField(
        default=False,
        help_text='Once true, this instance will never be re-queued or advanced again.',
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'workflow_instances'
        indexes = (
            models.Index(fields=['state']),
            models.Index(fields=['finalized']),
        )

    def __str__(self) -> str:  # DJ008
        return f'{self.definition.name}#{self.pk} ({self.state})'

    def finalize(self, state: str | None = None) -> None:
        """Mark this instance as fully done. Optionally set a final state."""
        if self.finalized:
            return
        self.finalized = True
        if state:
            self.state = state
            self.save(update_fields=['state', 'finalized'])
        else:
            self.save(update_fields=['finalized'])

    def get_steps(self) -> list[dict[str, Any]]:
        """Return the ordered list of steps from the workflow definition."""
        return cast('list[dict[str, Any]]', self.definition.definition.get('steps', []))

    def get_current_step_index(self) -> int:
        """Return the index of ``self.current_step`` in the steps list, or raise."""
        for idx, step in enumerate(self.get_steps()):
            if step['id'] == self.current_step:
                return idx
        raise ValueError(f'Unknown current_step {self.current_step!r}')

    def get_next_step(self) -> str | None:
        """Return the step-ID of the next step, or None if at the end."""
        idx = self.get_current_step_index()
        steps = self.get_steps()
        if idx + 1 < len(steps):
            return cast('str', steps[idx + 1]['id'])
        return None

    def is_last_approval_step(self) -> bool:
        """Return True if the current step is the last Approval step in the workflow."""
        approval_ids = [step['id'] for step in self.get_steps() if step['type'] == 'Approval']
        return bool(approval_ids and self.current_step == approval_ids[-1])
