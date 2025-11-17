# workflows/services/executors/email.py
from __future__ import annotations

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


class EmailExecutor(AbstractStepExecutor):
    """Send an email using either a named template or a simple subject/body.

    Params (validated upstream):
      - recipients: CSV or iterable (required)
      - template: str (MailTemplates key)  OR  (subject + body) for custom mode
      - subject: optional override in template mode; required in custom mode
      - body: required in custom mode (plain text)
      - from_email: optional; defaults to settings.DEFAULT_FROM_EMAIL
      - cc, bcc: optional CSV/iterables
    """

    def do_execute(self, instance: WorkflowInstance, _signal: str | None) -> ExecutorResult:  # pragma: no cover
        step = next(n for n in instance.get_steps() if n['id'] == instance.current_step)
        params: dict[str, Any] = dict(step.get('params') or {})

        to = normalize_addresses(params.get('recipients'))
        cc = normalize_addresses(params.get('cc'))
        bcc = normalize_addresses(params.get('bcc'))
        from_email = (params.get('from_email') or getattr(settings, 'DEFAULT_FROM_EMAIL', None)) or None

        if not to:
            return ExecutorResult(
                status=State.FAILED,
                context={
                    'type': 'Email',
                    'status': 'failed',
                    'error': 'Missing recipients',
                    'outputs': {},
                },
            )

        # Build full ctx for human-facing templates (DICT, no .data)
        full: dict[str, Any] = build_context(instance)
        template_ctx: dict[str, Any] = {'ctx': full}
        dj = engines['django']

        template_key = (params.get('template') or '').strip()

        # ==================== Template mode (HTML body via MailTemplates) ====================
        if template_key:
            tpl = MailTemplates.get_by_key(template_key)
            if not tpl:
                return ExecutorResult(
                    status=State.FAILED,
                    context={
                        'type': 'Email',
                        'status': 'failed',
                        'error': f'Unknown template {template_key!r}',
                        'outputs': {},
                    },
                )

            # SUBJECT: plain text → disable autoescape explicitly
            subject_src = (params.get('subject') or f'[{instance.definition.name}] Notification').strip()
            subj_tpl_src = f'{{% autoescape off %}}{subject_src}{{% endautoescape %}}'
            try:
                subject = dj.from_string(subj_tpl_src).render(template_ctx).strip()
            except TemplateSyntaxError as exc:
                return ExecutorResult(
                    status=State.FAILED,
                    context={
                        'type': 'Email',
                        'status': 'failed',
                        'error': f'Subject template error: {exc}',
                        'outputs': {'mode': 'template', 'template': template_key},
                    },
                )
            except Exception as exc:  # noqa: BLE001
                return ExecutorResult(
                    status=State.FAILED,
                    context={
                        'type': 'Email',
                        'status': 'failed',
                        'error': str(exc),
                        'outputs': {'mode': 'template', 'template': template_key},
                    },
                )

            try:
                payload = EmailPayload(
                    subject=subject,
                    to=to,
                    template_html=tpl,    # HTML rendering keeps autoescape
                    context=template_ctx,  # full ctx for templates
                    from_email=from_email,
                    cc=cc,
                    bcc=bcc,
                )
                send_email(payload)
            except Exception as exc:  # noqa: BLE001
                return ExecutorResult(
                    status=State.FAILED,
                    context={
                        'type': 'Email',
                        'status': 'failed',
                        'error': str(exc),
                        'outputs': {
                            'mode': 'template',
                            'template': template_key,
                            'to': list(to),
                            'cc': list(cc),
                            'bcc': list(bcc),
                        },
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
                        'to': list(to),
                        'cc': list(cc),
                        'bcc': list(bcc),
                        'email': 'Sent',
                    },
                },
            )

        # ==================== Custom mode (PLAIN TEXT body) ====================
        subject_src = (params.get('subject') or '').strip()
        body_src = (params.get('body') or '').strip()
        if not subject_src or not body_src:
            return ExecutorResult(
                status=State.FAILED,
                context={
                    'type': 'Email',
                    'status': 'failed',
                    'error': 'Missing subject/body for custom email',
                    'outputs': {},
                },
            )

        # SUBJECT/BODY: plain text → disable autoescape explicitly
        subj_tpl_src = f'{{% autoescape off %}}{subject_src}{{% endautoescape %}}'
        body_tpl_src = f'{{% autoescape off %}}{body_src}{{% endautoescape %}}'

        try:
            subject = dj.from_string(subj_tpl_src).render(template_ctx).strip()
            body = dj.from_string(body_tpl_src).render(template_ctx)
        except TemplateSyntaxError as exc:
            return ExecutorResult(
                status=State.FAILED,
                context={
                    'type': 'Email',
                    'status': 'failed',
                    'error': f'Template syntax error: {exc}',
                    'outputs': {'mode': 'custom'},
                },
            )
        except Exception as exc:  # noqa: BLE001
            return ExecutorResult(
                status=State.FAILED,
                context={
                    'type': 'Email',
                    'status': 'failed',
                    'error': str(exc),
                    'outputs': {'mode': 'custom'},
                },
            )

        try:
            send_simple(
                subject=subject,
                body=body,
                to=to,
                cc=cc,
                bcc=bcc,
                from_email=from_email,
            )
        except Exception as exc:  # noqa: BLE001
            return ExecutorResult(
                status=State.FAILED,
                context={
                    'type': 'Email',
                    'status': 'failed',
                    'error': str(exc),
                    'outputs': {'mode': 'custom', 'to': list(to), 'cc': list(cc), 'bcc': list(bcc)},
                },
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
                    'to': list(to),
                    'cc': list(cc),
                    'bcc': list(bcc),
                    'email': 'Sent',
                },
            },
        )
