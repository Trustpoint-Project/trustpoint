"""Central status transitions for Workflow 2 instances and runs."""
# ruff: noqa: D102

from __future__ import annotations

from typing import ClassVar

from workflows2.models import Workflow2Instance, Workflow2Run


class WorkflowInstanceTransitionService:
    """Apply Workflow 2 instance status changes consistently."""

    WAITING_STATUSES: ClassVar[set[str]] = {
        Workflow2Instance.STATUS_AWAITING,
        Workflow2Instance.STATUS_PAUSED,
    }
    ACTIVE_STATUSES: ClassVar[set[str]] = {
        Workflow2Instance.STATUS_QUEUED,
        Workflow2Instance.STATUS_RUNNING,
    }
    TERMINAL_STATUSES: ClassVar[set[str]] = {
        Workflow2Instance.STATUS_FINISHED,
        Workflow2Instance.STATUS_APPROVED,
        Workflow2Instance.STATUS_REJECTED,
        Workflow2Instance.STATUS_TIMED_OUT,
        Workflow2Instance.STATUS_STOPPED,
        Workflow2Instance.STATUS_CANCELLED,
    }
    RESUMABLE_STATUSES: ClassVar[set[str]] = {
        Workflow2Instance.STATUS_ERROR,
        Workflow2Instance.STATUS_PAUSED,
    }

    @classmethod
    def is_terminal(cls, status: str) -> bool:
        return status in cls.TERMINAL_STATUSES

    @classmethod
    def is_resumable(cls, status: str) -> bool:
        return status in cls.RESUMABLE_STATUSES

    @classmethod
    def mark_queued(cls, instance: Workflow2Instance) -> None:
        cls._set(instance, status=Workflow2Instance.STATUS_QUEUED)

    @classmethod
    def mark_running(cls, instance: Workflow2Instance) -> None:
        cls._set(instance, status=Workflow2Instance.STATUS_RUNNING)

    @classmethod
    def mark_waiting_for_approval(cls, instance: Workflow2Instance, *, step_id: str) -> None:
        cls._set(instance, status=Workflow2Instance.STATUS_AWAITING, current_step=step_id)

    @classmethod
    def mark_paused(cls, instance: Workflow2Instance, *, reason: str, message: str, next_step: str = '') -> None:
        cls._set(
            instance,
            status=Workflow2Instance.STATUS_PAUSED,
            current_step=next_step,
            reason=reason,
            message=message,
        )

    @classmethod
    def mark_finished(cls, instance: Workflow2Instance) -> None:
        cls._set(instance, status=Workflow2Instance.STATUS_FINISHED, current_step='')

    @classmethod
    def mark_approved(cls, instance: Workflow2Instance, *, reason: str = '', message: str = '') -> None:
        cls._set(
            instance,
            status=Workflow2Instance.STATUS_APPROVED,
            current_step='',
            reason=reason,
            message=message,
        )

    @classmethod
    def mark_rejected(cls, instance: Workflow2Instance, *, reason: str, message: str) -> None:
        cls._set(
            instance,
            status=Workflow2Instance.STATUS_REJECTED,
            current_step='',
            reason=reason,
            message=message,
        )

    @classmethod
    def mark_timed_out(cls, instance: Workflow2Instance, *, reason: str, message: str) -> None:
        cls._set(
            instance,
            status=Workflow2Instance.STATUS_TIMED_OUT,
            current_step='',
            reason=reason,
            message=message,
        )

    @classmethod
    def mark_error(
        cls,
        instance: Workflow2Instance,
        *,
        reason: str,
        message: str,
        current_step: str | None = None,
    ) -> None:
        cls._set(
            instance,
            status=Workflow2Instance.STATUS_ERROR,
            current_step=instance.current_step if current_step is None else current_step,
            reason=reason,
            message=message,
        )

    @classmethod
    def mark_stopped(cls, instance: Workflow2Instance, *, reason: str, message: str) -> None:
        cls._set(
            instance,
            status=Workflow2Instance.STATUS_STOPPED,
            current_step='',
            reason=reason,
            message=message,
        )

    @classmethod
    def mark_cancelled(cls, instance: Workflow2Instance) -> None:
        cls._set(
            instance,
            status=Workflow2Instance.STATUS_CANCELLED,
            current_step='',
            reason='cancelled',
            message=instance.status_message,
        )

    @classmethod
    def apply_terminal_status(cls, instance: Workflow2Instance, *, status: str, reason: str, message: str) -> None:
        if status == Workflow2Instance.STATUS_FINISHED:
            cls.mark_finished(instance)
            return
        if status == Workflow2Instance.STATUS_APPROVED:
            cls.mark_approved(instance, reason=reason, message=message)
            return
        if status == Workflow2Instance.STATUS_REJECTED:
            cls.mark_rejected(instance, reason=reason, message=message)
            return
        if status == Workflow2Instance.STATUS_ERROR:
            cls.mark_error(instance, reason=reason, message=message, current_step=instance.current_step)
            return
        if status == Workflow2Instance.STATUS_TIMED_OUT:
            cls.mark_timed_out(instance, reason=reason, message=message)
            return
        if status == Workflow2Instance.STATUS_STOPPED:
            cls.mark_stopped(instance, reason=reason, message=message)
            return

        msg = f'Unsupported terminal workflow status: {status}'
        raise ValueError(msg)

    @classmethod
    def _set(
        cls,
        instance: Workflow2Instance,
        *,
        status: str,
        current_step: str | None = None,
        reason: str = '',
        message: str = '',
    ) -> None:
        instance.status = status
        if current_step is not None:
            instance.current_step = current_step
        instance.status_reason = reason[:100]
        instance.status_message = message


class WorkflowRunTransitionService:
    """Derive aggregate run status from instance statuses."""

    ACTIVE_STATUSES: ClassVar[tuple[str, ...]] = (
        Workflow2Run.STATUS_QUEUED,
        Workflow2Run.STATUS_RUNNING,
    )
    BLOCKED_STATUSES: ClassVar[tuple[str, ...]] = (
        Workflow2Run.STATUS_AWAITING,
        Workflow2Run.STATUS_PAUSED,
        Workflow2Run.STATUS_ERROR,
    )
    TERMINAL_STATUSES: ClassVar[tuple[str, ...]] = (
        Workflow2Run.STATUS_FINISHED,
        Workflow2Run.STATUS_APPROVED,
        Workflow2Run.STATUS_REJECTED,
        Workflow2Run.STATUS_TIMED_OUT,
        Workflow2Run.STATUS_CANCELLED,
        Workflow2Run.STATUS_STOPPED,
    )

    @classmethod
    def derive_status(cls, statuses: list[str]) -> str:
        status_set = set(statuses)
        priority = (
            (Workflow2Instance.STATUS_REJECTED, Workflow2Run.STATUS_REJECTED),
            (Workflow2Instance.STATUS_TIMED_OUT, Workflow2Run.STATUS_TIMED_OUT),
            (Workflow2Instance.STATUS_ERROR, Workflow2Run.STATUS_ERROR),
            (Workflow2Instance.STATUS_PAUSED, Workflow2Run.STATUS_PAUSED),
            (Workflow2Instance.STATUS_AWAITING, Workflow2Run.STATUS_AWAITING),
            (Workflow2Instance.STATUS_RUNNING, Workflow2Run.STATUS_RUNNING),
            (Workflow2Instance.STATUS_QUEUED, Workflow2Run.STATUS_QUEUED),
            (Workflow2Instance.STATUS_STOPPED, Workflow2Run.STATUS_STOPPED),
        )
        for instance_status, run_status in priority:
            if instance_status in status_set:
                return run_status

        if statuses and all(status == Workflow2Instance.STATUS_CANCELLED for status in statuses):
            return Workflow2Run.STATUS_CANCELLED
        if Workflow2Instance.STATUS_APPROVED in status_set:
            return Workflow2Run.STATUS_APPROVED
        return Workflow2Run.STATUS_FINISHED

    @classmethod
    def is_finalized(cls, run_status: str) -> bool:
        return run_status in cls.TERMINAL_STATUSES


def save_instance_status(instance: Workflow2Instance, *, extra_fields: list[str] | None = None) -> None:
    """Persist an instance after transition service mutation."""
    fields = ['status', 'current_step', 'status_reason', 'status_message', 'updated_at']
    if extra_fields:
        fields = [*extra_fields, *fields]
    instance.save(update_fields=fields)
