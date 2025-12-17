"""Email step executor."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from django.conf import settings
from django.template import TemplateSyntaxError, engines

from util.email import (
    EmailPayload,
    MailTemplates,
    normalize_addresses,
    send_email,
    send_simple,
)
from workflows.models import State
from workflows.services.context import build_context
from workflows.services.executors.factory import AbstractStepExecutor
from workflows.services.types import ExecutorResult

if TYPE_CHECKING:
    from workflows.models import WorkflowInstance


@dataclass(frozen=True)
class EmailParts:
    """Internal container for resolved email components."""

    to: tuple[str, ...]
    cc: tuple[str, ...]
    bcc: tuple[str, ...]
    from_email: str | None
    template_ctx: dict[str, Any]
    dj: Any


class EmailExecutor(AbstractStepExecutor):
    """Send an email using either a named template or a simple subject/body."""

    def do_execute(self, instance: WorkflowInstance, _signal: str | None) -> ExecutorResult:
        """Execute the email step.

        Args:
            instance: Workflow instance being executed.
            _signal: Optional signal (unused for email steps).

        Returns:
            ExecutorResult describing the outcome of sending the email.
        """
        step = next((s for s in instance.get_steps() if s.get('id') == instance.current_step), None)
        if step is None:
            msg = f'Unknown current step id {instance.current_step!r}'
            raise ValueError(msg)

        params: dict[str, Any] = dict(step.get('params') or {})

        parts = self._prepare_recipients_and_context(params, instance)
        if not parts.to:
            return self._error_result('Missing recipients')

        template_key = (params.get('template') or '').strip()

        if template_key:
            return self._send_template_email(params, template_key, parts)

        return self._send_custom_email(params, parts)

    # ---------------------- internal helpers ---------------------- #

    @staticmethod
    def _prepare_recipients_and_context(params: dict[str, Any], instance: WorkflowInstance) -> EmailParts:
        """Prepare normalized recipients and template context."""
        to = normalize_addresses(params.get('recipients'))
        cc = normalize_addresses(params.get('cc'))
        bcc = normalize_addresses(params.get('bcc'))
        from_email = (params.get('from_email') or getattr(settings, 'DEFAULT_FROM_EMAIL', None)) or None

        full: dict[str, Any] = build_context(instance)
        template_ctx = {'ctx': full}
        dj = engines['django']

        return EmailParts(
            to=to,
            cc=cc,
            bcc=bcc,
            from_email=from_email,
            template_ctx=template_ctx,
            dj=dj,
        )

    @staticmethod
    def _error_result(message: str, *, outputs: dict[str, Any] | None = None) -> ExecutorResult:
        """Return a standardized FAILED result for this email step.

        Args:
            message: Human-readable error description.
            outputs: Optional additional output fields to include in the context.

        Returns:
            ExecutorResult with FAILED state and error details.
        """
        return ExecutorResult(
            status=State.FAILED,
            context={
                'type': 'Email',
                'status': 'failed',
                'error': message,
                'outputs': outputs or {},
            },
        )

    # ---------------------- template mode ---------------------- #

    def _send_template_email(
        self,
        params: dict[str, Any],
        template_key: str,
        parts: EmailParts,
    ) -> ExecutorResult:
        """Handle template-based email sending."""
        tpl = MailTemplates.get_by_key(template_key)
        if not tpl:
            return self._error_result(
                f'Unknown template {template_key!r}',
                outputs={},
            )

        subject_src = (params.get('subject') or 'Notification').strip()
        subj_tpl_src = f'{{% autoescape off %}}{subject_src}{{% endautoescape %}}'

        try:
            subject = parts.dj.from_string(subj_tpl_src).render(parts.template_ctx).strip()
        except TemplateSyntaxError as exc:
            return self._error_result(
                f'Subject template error: {exc}',
                outputs={'mode': 'template', 'template': template_key},
            )
        except Exception as exc:  # noqa: BLE001
            return self._error_result(
                str(exc),
                outputs={'mode': 'template', 'template': template_key},
            )

        try:
            payload = EmailPayload(
                subject=subject,
                to=parts.to,
                template_html=tpl,
                context=parts.template_ctx,
                from_email=parts.from_email,
                cc=parts.cc,
                bcc=parts.bcc,
            )
            send_email(payload)
        except Exception as exc:  # noqa: BLE001
            return self._error_result(
                str(exc),
                outputs={
                    'mode': 'template',
                    'template': template_key,
                    'to': list(parts.to),
                    'cc': list(parts.cc),
                    'bcc': list(parts.bcc),
                },
            )

        return ExecutorResult(
            status=State.PASSED,
            context={
                'type': 'Email',
                'status': 'Sent',
                'error': None,
                'outputs': {
                    'mode': 'template',
                    'template': template_key,
                    'subject': subject,
                    'to': list(parts.to),
                    'cc': list(parts.cc),
                    'bcc': list(parts.bcc),
                    'email': 'Sent',
                },
            },
        )

    # ---------------------- custom/plain-text mode ---------------------- #

    def _send_custom_email(
        self,
        params: dict[str, Any],
        parts: EmailParts,
    ) -> ExecutorResult:
        """Handle plain-text email sending."""
        subject_src = (params.get('subject') or '').strip()
        body_src = (params.get('body') or '').strip()
        if not subject_src or not body_src:
            return self._error_result('Missing subject/body for custom email')

        subj_tpl_src = f'{{% autoescape off %}}{subject_src}{{% endautoescape %}}'
        body_tpl_src = f'{{% autoescape off %}}{body_src}{{% endautoescape %}}'

        try:
            subject = parts.dj.from_string(subj_tpl_src).render(parts.template_ctx).strip()
            body = parts.dj.from_string(body_tpl_src).render(parts.template_ctx)
        except TemplateSyntaxError as exc:
            return self._error_result(
                f'Template syntax error: {exc}',
                outputs={'mode': 'custom'},
            )
        except Exception as exc:  # noqa: BLE001
            return self._error_result(
                str(exc),
                outputs={'mode': 'custom'},
            )

        try:
            send_simple(
                subject=subject,
                body=body,
                to=parts.to,
                cc=parts.cc,
                bcc=parts.bcc,
                from_email=parts.from_email,
            )
        except Exception as exc:  # noqa: BLE001
            return self._error_result(
                str(exc),
                outputs={'mode': 'custom', 'to': list(parts.to), 'cc': list(parts.cc), 'bcc': list(parts.bcc)},
            )

        return ExecutorResult(
            status=State.PASSED,
            context={
                'type': 'Email',
                'status': 'Sent',
                'error': None,
                'outputs': {
                    'mode': 'custom',
                    'subject': subject,
                    'to': list(parts.to),
                    'cc': list(parts.cc),
                    'bcc': list(parts.bcc),
                    'email': 'Sent',
                },
            },
        )
