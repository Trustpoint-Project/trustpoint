from collections.abc import Mapping
from typing import Any

from django.conf import settings
from django.core.mail import EmailMultiAlternatives
from django.template.loader import render_to_string


class EmailService:
    """Render and send multipart (text+HTML) emails."""

    @staticmethod
    def send_email(
        subject: str,
        to: list[str],
        template_name: str,
        context: Mapping[str, Any],
        from_email: str | None = None,
        cc: list[str] | None = None,
        bcc: list[str] | None = None,
        attachments: list[tuple[str, bytes, str]] | None = None,
    ) -> None:
        """Send mail.

        :param subject: email subject
        :param to: list of recipient addresses
        :param template_name: base name for
            - templates/emails/{template_name}.txt
            - templates/emails/{template_name}.html
        :param context: template rendering context
        :param from_email: overrides DEFAULT_FROM_EMAIL if set
        :param cc: optional list of CC addresses
        :param bcc: optional list of BCC addresses
        :param attachments: list of (filename, content_bytes, mime_type)
        :raises: any exception on send failure
        """
        sender = from_email or settings.DEFAULT_FROM_EMAIL
        text_body = render_to_string(f'emails/{template_name}.txt', context)
        html_body = render_to_string(f'emails/{template_name}.html', context)

        message = EmailMultiAlternatives(
            subject=subject,
            body=text_body,
            from_email=sender,
            to=to,
            cc=cc or [],
            bcc=bcc or [],
        )
        message.attach_alternative(html_body, 'text/html')

        if attachments:
            for filename, content, mime in attachments:
                message.attach(filename, content, mime)

        # synchronous send
        message.send(fail_silently=False)
        print('SEND EMAIL2')
