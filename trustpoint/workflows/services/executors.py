from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from django.conf import settings

from util.email import (
    EmailPayload,
    MailTemplates,
    send_email,
    send_simple,  # <= we will add this helper in util/email.py below
)
from workflows.models import WorkflowInstance


# ---------------- Result contract ----------------

class ExecStatus:
    PASSED        = 'passed'         # proceed to next node
    WAITING      = 'waiting'       # pause (e.g. awaiting approval)
    FAIL      = 'fail'       # terminal failure
    APPROVED  = 'approved'   # terminal approval (engine sets Approved, does NOT finalize)
    REJECTED  = 'rejected'   # terminal rejection (engine sets Rejected, finalizes)
    COMPLETED = 'completed'  # terminal success (engine sets Completed, finalizes)


@dataclass(frozen=True)
class NodeResult:
    status: str
    context: Mapping[str, Any] | None = None
    message: str | None = None


# ---------------- Registry ----------------

class NodeExecutorFactory:
    """Registry of node-type → executor class."""

    _registry: dict[str, type['AbstractNodeExecutor']] = {}

    @classmethod
    def register(cls, node_type: str, executor_cls: type['AbstractNodeExecutor']) -> None:
        cls._registry[node_type] = executor_cls

    @classmethod
    def create(cls, node_type: str) -> 'AbstractNodeExecutor':
        executor_cls = cls._registry.get(node_type)
        if executor_cls is None:
            raise ValueError(f'No executor registered for node type {node_type!r}')
        return executor_cls()


# ---------------- Base class ----------------

class AbstractNodeExecutor:
    """Template for node executors."""

    def execute(self, instance: WorkflowInstance, signal: str | None = None) -> NodeResult:
        return self.do_execute(instance, signal)

    def do_execute(self, instance: WorkflowInstance, signal: str | None) -> NodeResult:
        raise NotImplementedError


# ---------------- Executors ----------------

class ApprovalExecutor(AbstractNodeExecutor):
    """
    Approval semantics live here:

    - First time without a signal → WAIT (engine sets AwaitingApproval).
    - signal == 'Rejected' → REJECTED terminal (engine finalizes).
    - signal == 'Approved' →
        * if this is the LAST Approval step in the workflow → APPROVED terminal.
          (engine sets Approved, moves pointer to *next* node so a subsequent
           advance_instance() continues automatically)
        * otherwise → OK (engine advances to next node immediately)
    """

    def do_execute(self, instance: WorkflowInstance, signal: str | None) -> NodeResult:
        if signal is None:
            return NodeResult(status=ExecStatus.WAITING, message='Awaiting approval')

        if signal == 'Rejected':
            return NodeResult(status=ExecStatus.REJECTED, message='Rejected by approver')

        if signal == 'Approved':
            if instance.is_last_approval_step():
                return NodeResult(status=ExecStatus.APPROVED)
            return NodeResult(status=ExecStatus.PASSED)

        # Unknown signal → keep waiting
        return NodeResult(status=ExecStatus.WAITING)


class EmailExecutor(AbstractNodeExecutor):
    """Sends email and continues.

    Supports:
      • template-based (preferred): params.template = MailTemplates key
      • simple/plain: params.subject + params.body (no template)
    """

    def do_execute(self, instance: WorkflowInstance, signal: str | None) -> NodeResult:
        definition: Mapping[str, Any] = instance.definition.definition or {}
        nodes = definition.get('nodes', [])
        node = next(n for n in nodes if n.get('id') == instance.current_step)
        params: Mapping[str, Any] = node.get('params') or {}

        recipients_raw = params.get('recipients')
        if not recipients_raw:
            return NodeResult(status=ExecStatus.PASSED)

        # normalize recipients
        if isinstance(recipients_raw, str):
            to = tuple(x.strip() for x in recipients_raw.split(',') if x.strip())
        elif isinstance(recipients_raw, (list, tuple)):
            to = tuple(str(x).strip() for x in recipients_raw if str(x).strip())
        else:
            to = ()
        if not to:
            return NodeResult(status=ExecStatus.PASSED)

        # shared context
        ctx: dict[str, Any] = {
            'instance': instance,
            'workflow': instance.definition,
            'payload': instance.payload or {},
            'step': instance.current_step,
            'state': instance.state,
        }
        extra = params.get('context')
        if isinstance(extra, dict):
            ctx.update(extra)

        from_email = params.get('from_email') or getattr(settings, 'DEFAULT_FROM_EMAIL', None)

        template_key = params.get('template')
        subject = (params.get('subject') or '').strip()
        body    = (params.get('body') or '').strip()

        if template_key:
            # template path via registry
            mt = MailTemplates.get_by_key(str(template_key))
            if mt is None:
                # Unknown template key → treat as no-op (or return FAIL if you prefer)
                return NodeResult(status=ExecStatus.PASSED)

            payload = EmailPayload(
                subject=subject or 'Notification',
                to=to,
                template_html=mt,
                context=ctx,
                from_email=from_email,
            )
            send_email(payload)
            return NodeResult(status=ExecStatus.PASSED)

        # Fallback: simple text mail (no template)
        if subject and body:
            send_simple(
                subject=subject,
                body=body,
                to=to,
                from_email=from_email,
                cc=params.get('cc', ()),
                bcc=params.get('bcc', ()),
            )
            return NodeResult(status=ExecStatus.PASSED)

        # Nothing to send
        return NodeResult(status=ExecStatus.PASSED)


class IssueCertificateExecutor(AbstractNodeExecutor):
    """Placeholder – succeeds immediately."""
    def do_execute(self, instance: WorkflowInstance, signal: str | None) -> NodeResult:
        return NodeResult(status=ExecStatus.PASSED)


class ConditionExecutor(AbstractNodeExecutor):
    def do_execute(self, instance: WorkflowInstance, signal: str | None) -> NodeResult:
        # TODO: evaluate expression and maybe branch
        return NodeResult(status=ExecStatus.PASSED)


class WebhookExecutor(AbstractNodeExecutor):
    def do_execute(self, instance: WorkflowInstance, signal: str | None) -> NodeResult:
        # TODO: call webhook and evaluate outcome
        return NodeResult(status=ExecStatus.PASSED)


class TimerExecutor(AbstractNodeExecutor):
    def do_execute(self, instance: WorkflowInstance, signal: str | None) -> NodeResult:
        # TODO: set deadline context and return WAIT
        return NodeResult(status=ExecStatus.PASSED)


# Registry
NodeExecutorFactory.register('Approval', ApprovalExecutor)
NodeExecutorFactory.register('Email', EmailExecutor)
NodeExecutorFactory.register('IssueCertificate', IssueCertificateExecutor)
NodeExecutorFactory.register('Condition', ConditionExecutor)
NodeExecutorFactory.register('Webhook', WebhookExecutor)
NodeExecutorFactory.register('Timer', TimerExecutor)
