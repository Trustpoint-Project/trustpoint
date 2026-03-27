"""Persist and advance Workflow 2 runtime state."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta
from typing import TYPE_CHECKING, Any

from django.db import transaction
from django.utils import timezone

from workflows2.engine.context import RuntimeContext
from workflows2.engine.types import StepRun
from workflows2.models import (
    Workflow2Approval,
    Workflow2Definition,
    Workflow2Instance,
    Workflow2Run,
    Workflow2StepRun,
)

if TYPE_CHECKING:
    from workflows2.engine.executor import WorkflowExecutor


@dataclass(frozen=True)
class StepResult:
    """Describe the result of advancing one workflow step."""

    run: StepRun
    terminal: bool


class WorkflowRuntimeService:
    """Crash-resumable runtime (DB checkpointing).

    Policy (Modified B):
      - Step exceptions => instance.status = FAILED (retryable), keep current_step
      - Failed is NOT treated as finalized in run aggregation (manual retry allowed)
      - Always persist a Workflow2StepRun row even on exception
    """

    def __init__(self, *, executor: WorkflowExecutor, max_steps_per_run: int = 200) -> None:
        """Initialize the runtime service with an executor and safety limit."""
        self.executor = executor
        self.max_steps_per_run = max_steps_per_run

    @transaction.atomic
    def recompute_run_status(self, run: Any) -> None:
        """Recompute the aggregate status for a workflow run."""
        self._recompute_run(run)

    @transaction.atomic
    def create_instance(
        self,
        *,
        definition: Workflow2Definition,
        event: dict[str, Any],
        initial_vars: dict[str, Any] | None = None,
        run: Any | None = None,
    ) -> Workflow2Instance:
        """Create a new workflow instance positioned at `workflow.start`."""
        wf = (definition.ir_json or {}).get('workflow') or {}
        start = wf.get('start')
        if not isinstance(start, str) or not start:
            msg = 'Definition IR missing workflow.start'
            raise ValueError(msg)

        kwargs: dict[str, Any] = {
            'definition': definition,
            'event_json': event,
            'vars_json': initial_vars or {},
            'status': Workflow2Instance.STATUS_QUEUED,
            'current_step': start,
            'run_count': 0,
        }
        if run is not None:
            kwargs['run'] = run

        inst = Workflow2Instance.objects.create(**kwargs)
        self._recompute_run_if_present(inst)
        return inst

    def run_instance(self, instance: Workflow2Instance) -> Workflow2Instance:
        """Advance an instance until it blocks or reaches a terminal state."""
        steps = 0
        while True:
            instance.refresh_from_db()

            if instance.status in {
                Workflow2Instance.STATUS_SUCCEEDED,
                Workflow2Instance.STATUS_REJECTED,
                Workflow2Instance.STATUS_FAILED,
                Workflow2Instance.STATUS_CANCELLED,
                Workflow2Instance.STATUS_AWAITING,
                Workflow2Instance.STATUS_PAUSED,
            }:
                return instance

            if not instance.current_step:
                instance.status = Workflow2Instance.STATUS_SUCCEEDED
                instance.save(update_fields=['status', 'updated_at'])
                self._recompute_run_if_present(instance)
                return instance

            if steps >= self.max_steps_per_run:
                instance.status = Workflow2Instance.STATUS_FAILED
                instance.save(update_fields=['status', 'updated_at'])
                self._recompute_run_if_present(instance)
                return instance

            self.run_one_step(instance)
            steps += 1

    @staticmethod
    def _raise_runtime_state_error(message: str) -> None:
        raise ValueError(message)

    @staticmethod
    def _raise_runtime_type_error(message: str) -> None:
        raise TypeError(message)

    def _persist_run_one_step_failure(self, instance: Workflow2Instance, exc: Exception) -> None:
        err = f'{type(exc).__name__}: {exc}'

        with transaction.atomic():
            instance = (
                Workflow2Instance.objects.select_for_update()
                .select_related('definition')
                .get(id=instance.id)
            )

            ir = instance.definition.ir_json if instance.definition_id else {}
            wf = (ir or {}).get('workflow') or {}
            steps_map = wf.get('steps') or {}

            step_id = instance.current_step or 'unknown'
            step = steps_map.get(step_id) if isinstance(steps_map, dict) else None
            step_type = 'unknown'
            if isinstance(step, dict):
                step_type = str(step.get('type') or 'unknown')

            run_index = int(instance.run_count) + 1

            Workflow2StepRun.objects.create(
                instance=instance,
                run_index=run_index,
                step_id=step_id,
                step_type=step_type,
                status='failed',
                outcome='',
                next_step='',
                vars_delta={},
                output=None,
                error=err,
                created_at=timezone.now(),
            )

            instance.run_count = run_index
            instance.status = Workflow2Instance.STATUS_FAILED
            instance.save(update_fields=['run_count', 'status', 'updated_at'])

            self._recompute_run_if_present(instance)

    @staticmethod
    def _expire_pending_approval_if_needed(approval: Workflow2Approval) -> bool:
        if approval.status != Workflow2Approval.STATUS_PENDING:
            return approval.status == Workflow2Approval.STATUS_EXPIRED

        expires_at = approval.expires_at
        now = timezone.now()
        if expires_at is None or expires_at > now:
            return False

        updated = Workflow2Approval.objects.filter(
            id=approval.id,
            status=Workflow2Approval.STATUS_PENDING,
            expires_at__isnull=False,
            expires_at__lte=now,
        ).update(
            status=Workflow2Approval.STATUS_EXPIRED,
            decided_at=now,
            decided_by='',
            comment='',
        )
        if updated:
            approval.status = Workflow2Approval.STATUS_EXPIRED
            approval.decided_at = now
            approval.decided_by = ''
            approval.comment = ''
            return True

        approval.refresh_from_db(fields=['status', 'decided_at', 'decided_by', 'comment'])
        return approval.status == Workflow2Approval.STATUS_EXPIRED

    @staticmethod
    def _load_approval_resolution_context(
        approval_id: Any,
        instance_id: Any,
    ) -> tuple[Workflow2Approval, Workflow2Instance]:
        approval = (
            Workflow2Approval.objects.select_for_update()
            .select_related('instance')
            .get(id=approval_id)
        )
        inst = (
            Workflow2Instance.objects.select_for_update()
            .select_related('definition')
            .get(id=instance_id)
        )
        return approval, inst

    @staticmethod
    def _approval_next_step(
        *,
        inst: Workflow2Instance,
        approval: Workflow2Approval,
        decision: str,
    ) -> tuple[str, dict[str, Any]]:
        ir = inst.definition.ir_json
        wf = (ir or {}).get('workflow') or {}
        steps_map = wf.get('steps') or {}
        transitions = (wf.get('transitions') or {}).get(approval.step_id)
        if not isinstance(transitions, dict) or transitions.get('kind') != 'by_outcome':
            msg = 'Approval step missing by_outcome transitions in IR'
            raise ValueError(msg)

        step = steps_map.get(approval.step_id)
        params = (step.get('params') or {}) if isinstance(step, dict) else {}
        selected_outcome = (
            params.get('approved_outcome')
            if decision == 'approved'
            else params.get('rejected_outcome')
        )
        if not isinstance(selected_outcome, str) or not selected_outcome:
            msg = f"Approval step missing configured outcome for decision '{decision}'"
            raise ValueError(msg)

        outcome_map = transitions.get('map') or {}
        if not isinstance(outcome_map, dict):
            msg = 'Invalid outcome map'
            raise TypeError(msg)

        next_step = outcome_map.get(selected_outcome)
        if not isinstance(next_step, str) or not next_step:
            msg = f"No route for approval outcome '{selected_outcome}'"
            raise ValueError(msg)

        return next_step, {
            'selected_outcome': selected_outcome,
            'decision': decision,
        }

    def _resolve_pending_approval_locked(
        self,
        *,
        inst: Workflow2Instance,
        approval: Workflow2Approval,
        decision: str,
        decided_by: str | None,
        comment: str | None,
    ) -> None:
        next_step, payload = self._approval_next_step(
            inst=inst,
            approval=approval,
            decision=decision,
        )

        approval.status = (
            Workflow2Approval.STATUS_APPROVED
            if decision == 'approved'
            else Workflow2Approval.STATUS_REJECTED
        )
        approval.decided_at = timezone.now()
        approval.decided_by = decided_by or ''
        approval.comment = comment or ''
        approval.save(update_fields=['status', 'decided_at', 'decided_by', 'comment'])

        run_index = int(inst.run_count) + 1
        terminal_reject = next_step == '$reject'
        terminal_end = next_step == '$end'
        next_step_id = None if terminal_end or terminal_reject else next_step

        step_run_status = (
            'rejected'
            if terminal_reject
            else 'succeeded'
            if terminal_end
            else 'continued'
        )
        payload.update(
            {
                'status': step_run_status,
                'next_step_id': next_step_id,
                'decided_by': decided_by,
                'comment': comment,
            }
        )
        self._create_approval_step_run(
            inst=inst,
            approval=approval,
            run_index=run_index,
            payload=payload,
        )
        self._apply_approval_result(
            inst=inst,
            run_index=run_index,
            next_step_id=next_step_id,
            terminal_reject=terminal_reject,
            terminal_end=terminal_end,
        )

    @staticmethod
    def _create_approval_step_run(
        *,
        inst: Workflow2Instance,
        approval: Workflow2Approval,
        run_index: int,
        payload: dict[str, Any],
    ) -> None:
        Workflow2StepRun.objects.create(
            instance=inst,
            run_index=run_index,
            step_id=approval.step_id,
            step_type='approval',
            status=payload['status'],
            outcome=payload['selected_outcome'] or '',
            next_step=payload['next_step_id'] or '',
            vars_delta={},
            output={
                'decision': payload['decision'],
                'selected_outcome': payload['selected_outcome'],
                'comment': payload['comment'] or '',
                'decided_by': payload['decided_by'] or '',
            },
            error='',
            created_at=timezone.now(),
        )

    def _apply_approval_result(
        self,
        *,
        inst: Workflow2Instance,
        run_index: int,
        next_step_id: str | None,
        terminal_reject: bool,
        terminal_end: bool,
    ) -> None:
        inst.run_count = run_index
        if terminal_reject:
            inst.status = Workflow2Instance.STATUS_REJECTED
            inst.current_step = ''
        elif terminal_end:
            inst.status = Workflow2Instance.STATUS_SUCCEEDED
            inst.current_step = ''
        else:
            inst.status = Workflow2Instance.STATUS_RUNNING
            inst.current_step = next_step_id or ''

        inst.save(update_fields=['run_count', 'status', 'current_step', 'updated_at'])
        self._recompute_run_if_present(inst)

    def run_one_step(self, instance: Workflow2Instance) -> StepResult:
        """Execute exactly one workflow step and persist the checkpoint."""
        try:
            with transaction.atomic():
                instance = (
                    Workflow2Instance.objects.select_for_update()
                    .select_related('definition')
                    .get(id=instance.id)
                )

                if instance.status in {
                    Workflow2Instance.STATUS_SUCCEEDED,
                    Workflow2Instance.STATUS_REJECTED,
                    Workflow2Instance.STATUS_CANCELLED,
                    Workflow2Instance.STATUS_AWAITING,
                    Workflow2Instance.STATUS_PAUSED,
                }:
                    msg = 'Instance is terminal/blocked; cannot run'
                    self._raise_runtime_state_error(msg)

                if not instance.current_step:
                    instance.status = Workflow2Instance.STATUS_SUCCEEDED
                    instance.save(update_fields=['status', 'updated_at'])
                    self._recompute_run_if_present(instance)
                    return StepResult(
                        run=StepRun(
                            run_index=int(instance.run_count) + 1,
                            step_id='(end)',
                            step_type='end',
                            status='succeeded',
                            outcome=None,
                            next_step=None,
                            vars_delta={},
                            output=None,
                            error=None,
                            created_at=timezone.now(),
                        ),
                        terminal=True,
                    )

                ir = instance.definition.ir_json
                wf = (ir or {}).get('workflow') or {}
                steps_map = wf.get('steps') or {}
                transitions = wf.get('transitions') or {}

                step_id = instance.current_step
                step = steps_map.get(step_id)
                if not isinstance(step, dict):
                    msg = f'Missing step definition: {step_id}'
                    self._raise_runtime_type_error(msg)

                ctx = RuntimeContext(event=instance.event_json, vars=dict(instance.vars_json))
                run_index = int(instance.run_count) + 1

                run = self.executor.execute_single_step(
                    ir=ir,
                    step_id=step_id,
                    run_index=run_index,
                    ctx=ctx,
                    transitions=transitions.get(step_id),
                )

                Workflow2StepRun.objects.create(
                    instance=instance,
                    run_index=run.run_index,
                    step_id=run.step_id,
                    step_type=run.step_type,
                    status=run.status,
                    outcome=run.outcome or '',
                    next_step=run.next_step or '',
                    vars_delta=run.vars_delta or {},
                    output=run.output,
                    error=run.error or '',
                    created_at=timezone.now(),
                )

                instance.vars_json = ctx.vars
                instance.run_count = run_index

                if run.status == 'awaiting':
                    self._ensure_approval(instance=instance, step_id=step_id)
                    instance.status = Workflow2Instance.STATUS_AWAITING
                    instance.current_step = step_id
                    instance.save(update_fields=['vars_json', 'run_count', 'status', 'current_step', 'updated_at'])
                    self._recompute_run_if_present(instance)
                    return StepResult(run=run, terminal=True)

                if run.next_step is None:
                    instance.status = Workflow2Instance.STATUS_SUCCEEDED
                    instance.current_step = ''
                    instance.save(update_fields=['vars_json', 'run_count', 'status', 'current_step', 'updated_at'])
                    self._recompute_run_if_present(instance)
                    return StepResult(run=run, terminal=True)

                instance.status = Workflow2Instance.STATUS_RUNNING
                instance.current_step = run.next_step or ''
                instance.save(update_fields=['vars_json', 'run_count', 'status', 'current_step', 'updated_at'])
                self._recompute_run_if_present(instance)
                return StepResult(run=run, terminal=False)

        except Exception as e:
            self._persist_run_one_step_failure(instance, e)
            raise

    def resolve_approval(
        self,
        *,
        approval: Workflow2Approval,
        decision: str,
        decided_by: str | None = None,
        comment: str | None = None,
    ) -> None:
        """Resolve an approval step and move the instance to its next state."""
        if decision not in {'approved', 'rejected'}:
            msg = "decision must be 'approved' or 'rejected'"
            raise ValueError(msg)

        expired = False
        with transaction.atomic():
            approval, inst = self._load_approval_resolution_context(
                approval.id,
                approval.instance_id,
            )

            if inst.status != Workflow2Instance.STATUS_AWAITING:
                msg = 'Instance must be awaiting to resolve approval'
                raise ValueError(msg)

            if self._expire_pending_approval_if_needed(approval):
                expired = True
            elif approval.status != Workflow2Approval.STATUS_PENDING:
                msg = 'Approval is already resolved'
                raise ValueError(msg)
            else:
                self._resolve_pending_approval_locked(
                    inst=inst,
                    approval=approval,
                    decision=decision,
                    decided_by=decided_by,
                    comment=comment,
                )

        if expired:
            msg = 'Approval has expired'
            raise ValueError(msg)

    def _ensure_approval(self, *, instance: Workflow2Instance, step_id: str) -> Workflow2Approval:
        ir = instance.definition.ir_json
        wf = (ir or {}).get('workflow') or {}
        steps_map = wf.get('steps') or {}
        step = steps_map.get(step_id) or {}
        params = (step.get('params') or {}) if isinstance(step, dict) else {}

        timeout_seconds = params.get('timeout_seconds', None)
        expires_at = None
        if isinstance(timeout_seconds, int) and timeout_seconds > 0:
            expires_at = timezone.now() + timedelta(seconds=timeout_seconds)

        obj, _ = Workflow2Approval.objects.get_or_create(
            instance=instance,
            step_id=step_id,
            defaults={'status': Workflow2Approval.STATUS_PENDING, 'expires_at': expires_at},
        )
        return obj

    def _recompute_run_if_present(self, instance: Workflow2Instance) -> None:
        run_id = getattr(instance, 'run_id', None)
        if not run_id:
            return

        run = Workflow2Run.objects.select_for_update().get(id=run_id)
        self._recompute_run(run)

    @staticmethod
    def _recompute_run(run: Any) -> None:
        insts = list(Workflow2Instance.objects.filter(run=run).only('status'))
        statuses = [i.status for i in insts]
        if not statuses:
            return

        run.status = WorkflowRuntimeService._derive_run_status(statuses)
        terminal_statuses = {'succeeded', 'rejected', 'cancelled', 'stopped'}
        run.finalized = run.status in terminal_statuses
        run.save(update_fields=['status', 'finalized', 'updated_at'])

    @staticmethod
    def _derive_run_status(statuses: list[str]) -> str:
        status_set = set(statuses)
        priority = (
            (Workflow2Instance.STATUS_REJECTED, Workflow2Run.STATUS_REJECTED),
            (Workflow2Instance.STATUS_PAUSED, Workflow2Run.STATUS_PAUSED),
            (Workflow2Instance.STATUS_FAILED, Workflow2Run.STATUS_FAILED),
            (Workflow2Instance.STATUS_AWAITING, Workflow2Run.STATUS_AWAITING),
            (Workflow2Instance.STATUS_RUNNING, Workflow2Run.STATUS_RUNNING),
            (Workflow2Instance.STATUS_QUEUED, Workflow2Run.STATUS_QUEUED),
        )

        # IMPORTANT: include PAUSED, and do NOT finalize FAILED/PAUSED/AWAITING
        for instance_status, run_status in priority:
            if instance_status in status_set:
                return run_status
        if all(status == Workflow2Instance.STATUS_CANCELLED for status in statuses):
            return Workflow2Run.STATUS_CANCELLED
        if all(status == Workflow2Instance.STATUS_STOPPED for status in statuses):
            return Workflow2Run.STATUS_STOPPED
        return Workflow2Run.STATUS_SUCCEEDED
