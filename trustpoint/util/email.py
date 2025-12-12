"""Email utility classes and functions for rendering and sending templates."""

from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import TYPE_CHECKING, Any, ClassVar, cast

from django.conf import settings
from django.core.mail import EmailMultiAlternatives, get_connection
from django.template.exceptions import TemplateDoesNotExist
from django.template.loader import render_to_string
from django.utils.html import strip_tags
from django.utils.translation import gettext_lazy as _

if TYPE_CHECKING:
    from collections.abc import Iterable, Mapping

Attachment = tuple[str, bytes, str]  # (filename, content, mimetype)


@dataclass(frozen=True)
class MailTemplate:
    """Represents a template base path with helpers for .txt and .html variants."""

    key: str  # name of template (e.g. "user_welcome")
    base: str  # template base path
    label: str  # label for UI

    def txt(self) -> str:
        """Return the plain-text template path."""
        return f'{self.base}.txt'

    def html(self) -> str:
        """Return the HTML template path."""
        return f'{self.base}.html'


class MailTemplates:
    """Registry of grouped mail templates."""

    # --- User ---
    USER_WELCOME: ClassVar[MailTemplate] = MailTemplate(
        key='user_welcome',
        base='emails/user/user_welcome',
        label=cast('str', _('User Welcome')),
    )
    USER_DELETE: ClassVar[MailTemplate] = MailTemplate(
        key='user_delete',
        base='emails/user/user_delete',
        label=cast('str', _('User Delete')),
    )

    # --- Certificate ---
    CERTIFICATE_ISSUED: ClassVar[MailTemplate] = MailTemplate(
        key='certificate_issued',
        base='emails/certificate/certificate_issued',
        label=cast('str', _('Certificate Issued')),
    )
    CERTIFICATE_REVOKED: ClassVar[MailTemplate] = MailTemplate(
        key='certificate_revoked',
        base='emails/certificate/certificate_revoked',
        label=cast('str', _('Certificate Revoked')),
    )

    # Groups/registry
    GROUPS: ClassVar[Mapping[str, tuple[MailTemplate, ...]]] = {
        'user': (USER_WELCOME, USER_DELETE),
        'certificate': (CERTIFICATE_ISSUED, CERTIFICATE_REVOKED),
    }

    @classmethod
    def get_user_templates(cls) -> list[MailTemplate]:
        """Return the list of user-related templates."""
        return list(cls.GROUPS['user'])

    @classmethod
    def get_certificate_templates(cls) -> list[MailTemplate]:
        """Return the list of certificate-related templates."""
        return list(cls.GROUPS['certificate'])

    @classmethod
    def all(cls) -> list[MailTemplate]:
        """Return all templates for all groups."""
        return [t for group in cls.GROUPS.values() for t in group]

    @classmethod
    def get_by_key(cls, key: str) -> MailTemplate | None:
        """Find a template by its key."""
        for t in cls.all():
            if t.key == key:
                return t
        return None


@dataclass(frozen=True)
class EmailPayload:
    """Immutable value object describing one outbound email.

    Attributes:
        subject: Subject line.
        to: Recipients.
        template_html: Django template base (we render .txt and .html).
        context: Template context (wrapped as read-only).
        from_email: Optional override; defaults to settings.DEFAULT_FROM_EMAIL.
        reply_to: Optional Reply-To addresses.
        cc: Optional CC recipients.
        bcc: Optional BCC recipients.
        attachments: Optional sequence of (filename, bytes, mimetype).
        headers: Optional extra headers (e.g., {"X-Tag": "welcome"}).
    """

    subject: str
    to: tuple[str, ...]
    template_html: MailTemplate
    context: Mapping[str, object] = MappingProxyType({})
    from_email: str | None = None
    reply_to: tuple[str, ...] = ()
    cc: tuple[str, ...] = ()
    bcc: tuple[str, ...] = ()
    attachments: tuple[Attachment, ...] = ()
    headers: Mapping[str, str] = MappingProxyType({})

    def __post_init__(self) -> None:
        """Validate and normalize fields after dataclass initialization."""
        if not isinstance(self.context, MappingProxyType):
            object.__setattr__(self, 'context', MappingProxyType(dict(self.context)))
        if not isinstance(self.headers, MappingProxyType):
            object.__setattr__(self, 'headers', MappingProxyType(dict(self.headers)))
        if not isinstance(self.to, tuple):
            object.__setattr__(self, 'to', tuple(self.to))
        if not isinstance(self.reply_to, tuple):
            object.__setattr__(self, 'reply_to', tuple(self.reply_to))
        if not isinstance(self.cc, tuple):
            object.__setattr__(self, 'cc', tuple(self.cc))
        if not isinstance(self.bcc, tuple):
            object.__setattr__(self, 'bcc', tuple(self.bcc))
        if not isinstance(self.attachments, tuple):
            object.__setattr__(self, 'attachments', tuple(self.attachments))


def _render_bodies(tpl: MailTemplate, context: Mapping[str, object]) -> tuple[str, str]:
    ctx = dict(context)
    try:
        text = render_to_string(tpl.txt(), ctx)
    except TemplateDoesNotExist:
        html = render_to_string(tpl.html(), ctx)
        return strip_tags(html), html
    else:
        html = render_to_string(tpl.html(), ctx)
        return text, html


def send_email(payload: EmailPayload, *, connection: Any = None) -> int:
    """Send a single email with HTML + text alternative (from templates)."""
    text, html = _render_bodies(payload.template_html, payload.context)

    msg = EmailMultiAlternatives(
        subject=payload.subject,
        body=text,
        from_email=payload.from_email or getattr(settings, 'DEFAULT_FROM_EMAIL', None),
        to=list(payload.to),
        cc=list(payload.cc),
        bcc=list(payload.bcc),
        headers=dict(payload.headers),
        reply_to=list(payload.reply_to),
        connection=connection,
    )
    msg.attach_alternative(html, 'text/html')

    for name, content, mimetype in payload.attachments:
        msg.attach(name, content, mimetype)

    return msg.send()


def send_simple(  # noqa: PLR0913 - Email service requires multiple parameters for standard email fields
    *,
    subject: str,
    body: str,
    to: Iterable[str],
    cc: Iterable[str] = (),
    bcc: Iterable[str] = (),
    from_email: str | None = None,
    connection: Any = None,
    attachments: Iterable[Attachment] = (),
) -> int:
    """Send a plain-text email without using a HTML/txt template pair."""
    msg = EmailMultiAlternatives(
        subject=subject,
        body=body,
        from_email=from_email or getattr(settings, 'DEFAULT_FROM_EMAIL', None),
        to=list(to),
        cc=list(cc),
        bcc=list(bcc),
        connection=connection,
    )
    for name, content, mimetype in attachments:
        msg.attach(name, content, mimetype)
    return msg.send()


def normalize_addresses(value: Any) -> tuple[str, ...]:
    """Accept CSV string or iterable; return tuple of non-empty, trimmed emails."""
    if not value:
        return ()
    parts = [p.strip() for p in value.split(',')] if isinstance(value, str) else [str(p).strip() for p in value]
    return tuple(p for p in parts if p)


def send_bulk(payloads: Iterable[EmailPayload]) -> int:
    """Send multiple template-based emails reusing one SMTP connection."""
    sent = 0
    with get_connection() as conn:
        for p in payloads:
            sent += send_email(p, connection=conn)
    return sent
