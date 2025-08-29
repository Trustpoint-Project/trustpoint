"""Email executor for workflow nodes."""

from __future__ import annotations

from typing import TYPE_CHECKING

from django.conf import settings
from util.email import (
    EmailPayload,
    MailTemplates,
    normalize_addresses,
    send_email,
    send_simple,
)

from workflows.services.executors.factory import AbstractNodeExecutor
from workflows.services.types import ExecStatus, NodeResult

if TYPE_CHECKING:
    # Application import used only for type checking to avoid import-time coupling.
    from workflows.models import WorkflowInstance


class EmailExecutor(AbstractNodeExecutor):
    """Send an email using either a named template or a simple subject/body.

    Supported parameters (validated by UI layer):
        - recipients: CSV or list (required)
        - template: str (MailTemplates key) OR
        - subject + body (plain text)
        - from_email: str (optional; defaults to settings.DEFAULT_FROM_EMAIL)
        - cc, bcc: CSV or list (optional)
    """

    def do_execute(self, instance: WorkflowInstance, _signal: str | None) -> NodeResult:  # pragma: no cover
        """Execute the email-sending step.

        Args:
            instance: The workflow instance driving this execution.
            _signal: Unused external signal for this executor.

        Returns:
            A NodeResult indicating success or failure, with context details.
        """
        # Load this node's params
        node = next(n for n in instance.get_steps() if n['id'] == instance.current_step)
        params = dict(node.get('params') or {})

        to = normalize_addresses(params.get('recipients'))
        cc = normalize_addresses(params.get('cc'))
        bcc = normalize_addresses(params.get('bcc'))
        from_email = (params.get('from_email') or getattr(settings, 'DEFAULT_FROM_EMAIL', None)) or None

        if not to:
            return NodeResult(status=ExecStatus.FAIL, context={'error': 'Missing recipients'})

        template_key = (params.get('template') or '').strip()

        try:
            if template_key:
                tpl = MailTemplates.get_by_key(template_key)
                if not tpl:
                    return NodeResult(
                        status=ExecStatus.FAIL,
                        context={'error': f'Unknown template {template_key!r}'},
                    )

                ctx = {
                    'instance': instance,
                    'workflow': instance.definition,
                    'payload': instance.payload or {},
                    'current_step': instance.current_step,
                    'state': instance.state,
                }
                payload = EmailPayload(
                    subject=f'[{instance.definition.name}] Notification',
                    to=to,
                    template_html=tpl,
                    context=ctx,
                    from_email=from_email,
                    cc=cc,
                    bcc=bcc,
                )
                send_email(payload)
            else:
                subject = (params.get('subject') or '').strip()
                body = (params.get('body') or '').strip()
                if not subject or not body:
                    return NodeResult(
                        status=ExecStatus.FAIL,
                        context={'error': 'Missing subject/body for simple email'},
                    )

                send_simple(
                    subject=subject,
                    body=body,
                    to=to,
                    cc=cc,
                    bcc=bcc,
                    from_email=from_email,
                )

        except Exception as exc:  # noqa: BLE001 — side-effectful I/O; normalize to FAIL
            return NodeResult(status=ExecStatus.FAIL, context={'error': str(exc)})

        # success → continue
        return NodeResult(status=ExecStatus.PASSED, context={'email': 'sent'})
