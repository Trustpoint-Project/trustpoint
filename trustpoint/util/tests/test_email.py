"""Test file for emails.py."""

from __future__ import annotations

from copy import deepcopy
from types import MappingProxyType
from typing import TYPE_CHECKING, Any, cast

import pytest
from django.core import mail
from django.template.loader import get_template
from util.email import (
    EmailPayload,
    MailTemplate,
    _render_bodies,
    send_bulk,
    send_email,
)

if TYPE_CHECKING:
    from pathlib import Path


def _write_template(tpldir: Path, relpath: str, content: str) -> None:
    """Helper to create a template file with given relative path and content."""
    p = tpldir / relpath
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding='utf-8')


@pytest.fixture
def templates_dir(settings: Any, tmp_path: Path) -> Path:
    """Provide a clean temporary template directory and point Django to it."""
    tdir = tmp_path / 'templates'
    tdir.mkdir(parents=True, exist_ok=True)

    engines = deepcopy(settings.TEMPLATES)
    engines[0]['DIRS'] = [str(tdir)]
    settings.TEMPLATES = engines
    return tdir


@pytest.fixture(autouse=True)
def locmem_email_backend(settings: Any) -> None:
    """Force Django to use locmem email backend for tests."""
    settings.EMAIL_BACKEND = 'django.core.mail.backends.locmem.EmailBackend'


@pytest.mark.django_db
def test_mailtemplate_helpers() -> None:
    """Ensure MailTemplate.txt() and .html() return correct paths."""
    tpl = MailTemplate(key='k', base='emails/foo/bar', label='Label')
    assert tpl.txt() == 'emails/foo/bar.txt'
    assert tpl.html() == 'emails/foo/bar.html'


@pytest.mark.django_db
def test_render_bodies_prefers_txt_when_present(templates_dir: Path) -> None:
    """Verify that _render_bodies prefers .txt when both txt and html exist."""
    base = 'emails/welcome'
    _write_template(templates_dir, f'{base}.txt', 'Hello {{ name }} (TEXT)')
    _write_template(templates_dir, f'{base}.html', '<h1>Hello {{ name }}</h1> (HTML)')

    assert get_template(f'{base}.txt') is not None
    assert get_template(f'{base}.html') is not None

    tpl = MailTemplate(key='welcome', base=base, label='Welcome')

    text, html = _render_bodies(tpl, {'name': 'Alex'})
    assert 'Hello Alex (TEXT)' in text
    assert '<h1>Hello Alex</h1>' in html


@pytest.mark.django_db
def test_render_bodies_falls_back_if_txt_missing(templates_dir: Path) -> None:
    """Verify that _render_bodies falls back to HTML and strip_tags when txt missing."""
    base = 'emails/only_html'
    _write_template(templates_dir, f'{base}.html', '<p>Hi <b>{{ name }}</b></p>')
    tpl = MailTemplate(key='only_html', base=base, label='Only HTML')

    text, html = _render_bodies(tpl, {'name': 'Sam'})
    assert 'Hi Sam' in text
    assert '<p>Hi <b>Sam</b></p>' in html


@pytest.mark.django_db
def test_send_email_builds_multipart_and_uses_locmem(templates_dir: Path) -> None:
    """Ensure send_email renders templates and sends a multipart email."""
    base = 'emails/notice'
    _write_template(templates_dir, f'{base}.txt', 'Notice for {{ who }}.')
    _write_template(templates_dir, f'{base}.html', '<strong>Notice</strong> for {{ who }}.')

    tpl = MailTemplate(key='notice', base=base, label='Notice')
    payload = EmailPayload(
        subject='A subject',
        to=('u@example.com',),
        template_html=tpl,
        context={'who': 'you'},
        from_email='no-reply@example.com',
        cc=('cc@example.com',),
        bcc=('audit@example.com',),
        headers={'X-Tag': 'test'},
    )

    sent = send_email(payload)
    assert sent == 1
    assert len(mail.outbox) == 1

    m = cast('EmailMultiAlternatives', mail.outbox[0])
    assert m.subject == 'A subject'
    assert m.to == ['u@example.com']
    assert m.cc == ['cc@example.com']
    assert m.bcc == ['audit@example.com']
    assert m.alternatives is not None
    assert len(m.alternatives) >= 1

    content, mimetype = m.alternatives[0]
    assert mimetype == 'text/html'

    # Ensure we compare against a str (mypy: content may be bytes | Message | str)
    content_text = content.decode() if isinstance(content, bytes) else str(content)

    assert 'Notice' in content_text


@pytest.mark.django_db
def test_send_bulk_sends_multiple(templates_dir: Path) -> None:
    """Ensure send_bulk sends all payloads and accumulates sent count."""
    base = 'emails/bulk'
    _write_template(templates_dir, f'{base}.html', '<p>Hello {{ n }}</p>')
    tpl = MailTemplate(key='bulk', base=base, label='Bulk')

    payloads = [
        EmailPayload(subject='S1', to=('a@example.com',), template_html=tpl, context={'n': 1}),
        EmailPayload(subject='S2', to=('b@example.com',), template_html=tpl, context={'n': 2}),
    ]

    expectend_sent = 2
    sent = send_bulk(payloads)
    assert sent == expectend_sent

    assert len(mail.outbox) == expectend_sent
    assert mail.outbox[0].subject == 'S1'
    assert mail.outbox[1].subject == 'S2'


@pytest.mark.django_db
def test_emailpayload_post_init_normalizes_types(templates_dir: Path) -> None:
    """Verify that EmailPayload.__post_init__ normalizes lists to tuples and dicts to MappingProxyType."""
    base = 'emails/norm'
    _write_template(templates_dir, f'{base}.html', '<p>x</p>')
    tpl = MailTemplate(key='norm', base=base, label='Norm')

    payload = EmailPayload(
        subject='S',
        to=('u@example.com',),
        template_html=tpl,
        context={'a': 1},
        reply_to=['r@example.com'],  # type: ignore[arg-type]
        cc=['c@example.com'],  # type: ignore[arg-type]
        bcc=['b@example.com'],  # type: ignore[arg-type]
        attachments=[('name.txt', b'bytes', 'text/plain')],  # type: ignore[arg-type]
        headers={'X': '1'},
    )

    assert isinstance(payload.to, tuple)
    assert isinstance(payload.reply_to, tuple)
    assert isinstance(payload.cc, tuple)
    assert isinstance(payload.bcc, tuple)
    assert isinstance(payload.attachments, tuple)
    assert isinstance(payload.context, MappingProxyType)
    assert isinstance(payload.headers, MappingProxyType)
