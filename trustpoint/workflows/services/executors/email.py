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

from workflows.services.context import build_context
from workflows.services.executors.factory import AbstractNodeExecutor
from workflows.services.types import ExecStatus, NodeResult

if TYPE_CHECKING:
    from workflows.models import WorkflowInstance


def _render_plain(template_src: str, context: dict[str, Any]) -> str:
    """Render a Django template string with autoescape disabled (plain text)."""
    dj = engines['django']
    tpl = dj.from_string('{% autoescape off %}' + (template_src or '') + '{% endautoescape %}')
    return tpl.render(context)


class EmailExecutor(AbstractNodeExecutor):
    """Send an email using either a named template or a simple subject/body.

    Params (validated upstream):
      - recipients: CSV or iterable (required)
      - template: str (MailTemplates key)  OR  (subject + body) for custom mode
      - subject: optional override in template mode; required in custom mode
      - body: required in custom mode
      - from_email: optional; defaults to settings.DEFAULT_FROM_EMAIL
      - cc, bcc: optional CSV/iterables
    """

    def do_execute(self, instance: WorkflowInstance, _signal: str | None) -> NodeResult:
        # Resolve params
        node = next(n for n in instance.get_steps() if n['id'] == instance.current_step)
        params: dict[str, Any] = dict(node.get('params') or {})

        to = normalize_addresses(params.get('recipients'))
        cc = normalize_addresses(params.get('cc'))
        bcc = normalize_addresses(params.get('bcc'))
        from_email = (params.get('from_email') or getattr(settings, 'DEFAULT_FROM_EMAIL', None)) or None

        if not to:
            return NodeResult(status=ExecStatus.FAIL, context={'error': 'Missing recipients'})

        # Canonical context (single-path: {{ ctx.* }})
        ctx = build_context(instance).data
        template_ctx: dict[str, Any] = {'ctx': ctx}

        template_key = (params.get('template') or '').strip()

        # ==================== Template mode (HTML via util.email.send_email) ====================
        if template_key:
            tpl = MailTemplates.get_by_key(template_key)
            if not tpl:
                return NodeResult(status=ExecStatus.FAIL, context={'error': f'Unknown template {template_key!r}'})

            # Subject is plain text; render with autoescape OFF
            subject_src = (params.get('subject') or f'[{instance.definition.name}] Notification').strip()
            try:
                subject = _render_plain(subject_src, template_ctx).strip()
            except TemplateSyntaxError as exc:
                return NodeResult(
                    status=ExecStatus.FAIL,
                    context={'mode': 'template', 'template': template_key, 'error': f'Subject template error: {exc}'},
                )
            except Exception as exc:  # noqa: BLE001
                return NodeResult(
                    status=ExecStatus.FAIL,
                    context={'mode': 'template', 'template': template_key, 'error': str(exc)},
                )

            try:
                payload = EmailPayload(
                    subject=subject,
                    to=to,
                    template_html=tpl,
                    context=template_ctx,
                    from_email=from_email,
                    cc=cc,
                    bcc=bcc,
                )
                send_email(payload)
            except Exception as exc:  # noqa: BLE001
                return NodeResult(
                    status=ExecStatus.FAIL,
                    context={'mode': 'template', 'template': template_key, 'error': str(exc)},
                )

            return NodeResult(
                status=ExecStatus.PASSED,
                context={
                    'mode': 'template',
                    'template': template_key,
                    'subject': subject,
                    'to': list(to),
                    'cc': list(cc),
                    'bcc': list(bcc),
                    'email': 'sent',
                },
            )

        # ==================== Custom mode (plain text; autoescape OFF) ====================
        subject_src = (params.get('subject') or '').strip()
        body_src = (params.get('body') or '').strip()
        if not subject_src or not body_src:
            return NodeResult(
                status=ExecStatus.FAIL,
                context={'error': 'Missing subject/body for custom email'},
            )

        try:
            subject = _render_plain(subject_src, template_ctx).strip()
            body = _render_plain(body_src, template_ctx)
        except TemplateSyntaxError as exc:
            return NodeResult(
                status=ExecStatus.FAIL,
                context={'mode': 'custom', 'error': f'Template syntax error: {exc}'},
            )
        except Exception as exc:  # noqa: BLE001
            return NodeResult(
                status=ExecStatus.FAIL,
                context={'mode': 'custom', 'error': str(exc)},
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
            return NodeResult(status=ExecStatus.FAIL, context={'mode': 'custom', 'error': str(exc)})

        return NodeResult(
            status=ExecStatus.PASSED,
            context={
                'mode': 'custom',
                'subject': subject,
                'to': list(to),
                'cc': list(cc),
                'bcc': list(bcc),
                'email': 'sent',
                'rendered': True,
            },
        )
