"""Email step executor."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from django.conf import settings
from django.template import TemplateSyntaxError, engines

from util.email import EmailPayload, MailTemplates, normalize_addresses, send_email, send_simple
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
            return self._error_result(
                'Missing recipients',
                email_outputs=self._stable_email_outputs(parts=parts, mode=None, template=None, subject=None),
            )

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
    def _stable_email_outputs(
        *,
        parts: EmailParts | None,
        mode: str | None,
        template: str | None,
        subject: str | None,
    ) -> dict[str, Any]:
        """Return a stable outputs.email shape for ctx.steps.<n>.outputs.email.*."""
        return {
            'mode': mode,
            'template': template,
            'subject': subject,
            'recipients': list(parts.to) if parts else [],
            'from': (parts.from_email if parts else None),
            'cc': list(parts.cc) if parts else [],
            'bcc': list(parts.bcc) if parts else [],
        }

    @staticmethod
    def _error_result(
        message: str,
        *,
        email_outputs: dict[str, Any] | None = None,
        outputs: dict[str, Any] | None = None,
    ) -> ExecutorResult:
        """Return a standardized FAILED result for this email step.

        Args:
            message: Human-readable error description.
            email_outputs: Stable outputs.email payload.
            outputs: Optional extra outputs to include (merged alongside email).

        Returns:
            ExecutorResult with FAILED state and error details.
        """
        out: dict[str, Any] = {}
        if outputs:
            out.update(outputs)

        out['email'] = email_outputs or {
            'mode': None,
            'template': None,
            'subject': None,
            'recipients': [],
            'from': None,
            'cc': [],
            'bcc': [],
        }

        return ExecutorResult(
            status=State.FAILED,
            context={
                'type': 'Email',
                'status': 'failed',
                'error': message,
                'outputs': out,
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
                email_outputs=self._stable_email_outputs(parts=parts, mode='template', template=template_key, subject=None),
            )

        subject_src = (params.get('subject') or 'Notification').strip()
        subj_tpl_src = f'{{% autoescape off %}}{subject_src}{{% endautoescape %}}'

        try:
            subject = parts.dj.from_string(subj_tpl_src).render(parts.template_ctx).strip()
        except TemplateSyntaxError as exc:
            return self._error_result(
                f'Subject template error: {exc}',
                email_outputs=self._stable_email_outputs(parts=parts, mode='template', template=template_key, subject=None),
            )
        except Exception as exc:  # noqa: BLE001
            return self._error_result(
                str(exc),
                email_outputs=self._stable_email_outputs(parts=parts, mode='template', template=template_key, subject=None),
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
                email_outputs=self._stable_email_outputs(parts=parts, mode='template', template=template_key, subject=subject),
            )

        return ExecutorResult(
            status=State.PASSED,
            context={
                'type': 'Email',
                'status': 'passed',
                'error': None,
                'outputs': {
                    'email': self._stable_email_outputs(
                        parts=parts,
                        mode='template',
                        template=template_key,
                        subject=subject,
                    ),
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
            return self._error_result(
                'Missing subject/body for custom email',
                email_outputs=self._stable_email_outputs(parts=parts, mode='custom', template=None, subject=None),
            )

        subj_tpl_src = f'{{% autoescape off %}}{subject_src}{{% endautoescape %}}'
        body_tpl_src = f'{{% autoescape off %}}{body_src}{{% endautoescape %}}'

        try:
            subject = parts.dj.from_string(subj_tpl_src).render(parts.template_ctx).strip()
            body = parts.dj.from_string(body_tpl_src).render(parts.template_ctx)
        except TemplateSyntaxError as exc:
            return self._error_result(
                f'Template syntax error: {exc}',
                email_outputs=self._stable_email_outputs(parts=parts, mode='custom', template=None, subject=None),
            )
        except Exception as exc:  # noqa: BLE001
            return self._error_result(
                str(exc),
                email_outputs=self._stable_email_outputs(parts=parts, mode='custom', template=None, subject=None),
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
                email_outputs=self._stable_email_outputs(parts=parts, mode='custom', template=None, subject=subject),
            )

        return ExecutorResult(
            status=State.PASSED,
            context={
                'type': 'Email',
                'status': 'passed',
                'error': None,
                'outputs': {
                    'email': self._stable_email_outputs(
                        parts=parts,
                        mode='custom',
                        template=None,
                        subject=subject,
                    ),
                },
            },
        )
