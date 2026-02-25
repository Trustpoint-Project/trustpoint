"""Tests for util/email_service.py."""

from typing import Any
from unittest.mock import Mock, patch

import pytest
from django.core import mail
from django.core.mail.message import EmailMultiAlternatives

from util.email_service import EmailService


@pytest.fixture(autouse=True)
def locmem_email_backend(settings: Any) -> None:
    """Force Django to use locmem email backend for tests."""
    settings.EMAIL_BACKEND = 'django.core.mail.backends.locmem.EmailBackend'


@pytest.fixture
def templates_dir(settings: Any, tmp_path: Any) -> Any:
    """Provide a clean temporary template directory and point Django to it."""
    from copy import deepcopy
    
    tdir = tmp_path / 'templates'
    tdir.mkdir(parents=True, exist_ok=True)
    
    engines = deepcopy(settings.TEMPLATES)
    engines[0]['DIRS'] = [str(tdir)]
    settings.TEMPLATES = engines
    
    # Create emails directory
    emails_dir = tdir / 'emails'
    emails_dir.mkdir(parents=True, exist_ok=True)
    
    return tdir


def _write_template(tpldir: Any, relpath: str, content: str) -> None:
    """Helper to create a template file with given relative path and content."""
    p = tpldir / relpath
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding='utf-8')


@pytest.mark.django_db
class TestEmailService:
    """Tests for EmailService class."""

    def test_send_email_basic(self, templates_dir: Any) -> None:
        """Test sending a basic email."""
        _write_template(templates_dir, 'emails/test.txt', 'Hello {{ name }}!')
        _write_template(templates_dir, 'emails/test.html', '<h1>Hello {{ name }}!</h1>')
        
        EmailService.send_email(
            subject='Test Subject',
            to=['recipient@example.com'],
            template_name='test',
            context={'name': 'World'},
        )
        
        assert len(mail.outbox) == 1
        msg = mail.outbox[0]
        assert msg.subject == 'Test Subject'
        assert msg.to == ['recipient@example.com']
        assert 'Hello World!' in msg.body
        assert len(msg.alternatives) == 1
        html_content, mime_type = msg.alternatives[0]
        assert mime_type == 'text/html'
        assert '<h1>Hello World!</h1>' in html_content

    def test_send_email_with_custom_from(self, templates_dir: Any) -> None:
        """Test sending email with custom from_email."""
        _write_template(templates_dir, 'emails/custom.txt', 'Test')
        _write_template(templates_dir, 'emails/custom.html', '<p>Test</p>')
        
        EmailService.send_email(
            subject='Custom From',
            to=['recipient@example.com'],
            template_name='custom',
            context={},
            from_email='custom@example.com',
        )
        
        assert len(mail.outbox) == 1
        assert mail.outbox[0].from_email == 'custom@example.com'

    def test_send_email_with_default_from(self, templates_dir: Any, settings: Any) -> None:
        """Test sending email with default from_email from settings."""
        settings.DEFAULT_FROM_EMAIL = 'default@example.com'
        
        _write_template(templates_dir, 'emails/default.txt', 'Test')
        _write_template(templates_dir, 'emails/default.html', '<p>Test</p>')
        
        EmailService.send_email(
            subject='Default From',
            to=['recipient@example.com'],
            template_name='default',
            context={},
        )
        
        assert len(mail.outbox) == 1
        assert mail.outbox[0].from_email == 'default@example.com'

    def test_send_email_with_cc(self, templates_dir: Any) -> None:
        """Test sending email with CC recipients."""
        _write_template(templates_dir, 'emails/cc.txt', 'Test')
        _write_template(templates_dir, 'emails/cc.html', '<p>Test</p>')
        
        EmailService.send_email(
            subject='With CC',
            to=['recipient@example.com'],
            template_name='cc',
            context={},
            cc=['cc1@example.com', 'cc2@example.com'],
        )
        
        assert len(mail.outbox) == 1
        assert mail.outbox[0].cc == ['cc1@example.com', 'cc2@example.com']

    def test_send_email_with_bcc(self, templates_dir: Any) -> None:
        """Test sending email with BCC recipients."""
        _write_template(templates_dir, 'emails/bcc.txt', 'Test')
        _write_template(templates_dir, 'emails/bcc.html', '<p>Test</p>')
        
        EmailService.send_email(
            subject='With BCC',
            to=['recipient@example.com'],
            template_name='bcc',
            context={},
            bcc=['bcc1@example.com', 'bcc2@example.com'],
        )
        
        assert len(mail.outbox) == 1
        assert mail.outbox[0].bcc == ['bcc1@example.com', 'bcc2@example.com']

    def test_send_email_with_cc_and_bcc(self, templates_dir: Any) -> None:
        """Test sending email with both CC and BCC recipients."""
        _write_template(templates_dir, 'emails/both.txt', 'Test')
        _write_template(templates_dir, 'emails/both.html', '<p>Test</p>')
        
        EmailService.send_email(
            subject='With Both',
            to=['recipient@example.com'],
            template_name='both',
            context={},
            cc=['cc@example.com'],
            bcc=['bcc@example.com'],
        )
        
        assert len(mail.outbox) == 1
        msg = mail.outbox[0]
        assert msg.cc == ['cc@example.com']
        assert msg.bcc == ['bcc@example.com']

    def test_send_email_with_attachments(self, templates_dir: Any) -> None:
        """Test sending email with attachments."""
        _write_template(templates_dir, 'emails/attach.txt', 'Test')
        _write_template(templates_dir, 'emails/attach.html', '<p>Test</p>')
        
        attachment_content = b'This is a test file content'
        
        EmailService.send_email(
            subject='With Attachment',
            to=['recipient@example.com'],
            template_name='attach',
            context={},
            attachments=[
                ('test.txt', attachment_content, 'text/plain'),
            ],
        )
        
        assert len(mail.outbox) == 1
        msg = mail.outbox[0]
        assert len(msg.attachments) == 1
        filename, content, mimetype = msg.attachments[0]
        assert filename == 'test.txt'
        # Content may be str or bytes depending on Django version
        if isinstance(content, bytes):
            assert content == attachment_content
        else:
            assert content == attachment_content.decode('utf-8')
        assert mimetype == 'text/plain'

    def test_send_email_with_multiple_attachments(self, templates_dir: Any) -> None:
        """Test sending email with multiple attachments."""
        _write_template(templates_dir, 'emails/multi_attach.txt', 'Test')
        _write_template(templates_dir, 'emails/multi_attach.html', '<p>Test</p>')
        
        EmailService.send_email(
            subject='Multiple Attachments',
            to=['recipient@example.com'],
            template_name='multi_attach',
            context={},
            attachments=[
                ('file1.txt', b'Content 1', 'text/plain'),
                ('file2.pdf', b'Content 2', 'application/pdf'),
                ('file3.jpg', b'Content 3', 'image/jpeg'),
            ],
        )
        
        assert len(mail.outbox) == 1
        msg = mail.outbox[0]
        assert len(msg.attachments) == 3

    def test_send_email_to_multiple_recipients(self, templates_dir: Any) -> None:
        """Test sending email to multiple recipients."""
        _write_template(templates_dir, 'emails/multi.txt', 'Test')
        _write_template(templates_dir, 'emails/multi.html', '<p>Test</p>')
        
        EmailService.send_email(
            subject='Multiple Recipients',
            to=['recipient1@example.com', 'recipient2@example.com', 'recipient3@example.com'],
            template_name='multi',
            context={},
        )
        
        assert len(mail.outbox) == 1
        msg = mail.outbox[0]
        assert len(msg.to) == 3
        assert 'recipient1@example.com' in msg.to
        assert 'recipient2@example.com' in msg.to
        assert 'recipient3@example.com' in msg.to

    def test_send_email_with_complex_context(self, templates_dir: Any) -> None:
        """Test sending email with complex context variables."""
        _write_template(
            templates_dir,
            'emails/complex.txt',
            'Hello {{ user.name }}! Your order #{{ order.id }} is {{ order.status }}.'
        )
        _write_template(
            templates_dir,
            'emails/complex.html',
            '<p>Hello {{ user.name }}! Your order #{{ order.id }} is {{ order.status }}.</p>'
        )
        
        EmailService.send_email(
            subject='Complex Context',
            to=['recipient@example.com'],
            template_name='complex',
            context={
                'user': {'name': 'John Doe'},
                'order': {'id': 12345, 'status': 'shipped'},
            },
        )
        
        assert len(mail.outbox) == 1
        msg = mail.outbox[0]
        assert 'Hello John Doe!' in msg.body
        assert 'order #12345' in msg.body
        assert 'is shipped' in msg.body

    def test_send_email_empty_context(self, templates_dir: Any) -> None:
        """Test sending email with empty context."""
        _write_template(templates_dir, 'emails/empty.txt', 'Static content')
        _write_template(templates_dir, 'emails/empty.html', '<p>Static content</p>')
        
        EmailService.send_email(
            subject='Empty Context',
            to=['recipient@example.com'],
            template_name='empty',
            context={},
        )
        
        assert len(mail.outbox) == 1
        assert 'Static content' in mail.outbox[0].body

    def test_send_email_none_cc_and_bcc(self, templates_dir: Any) -> None:
        """Test that None CC and BCC are handled as empty lists."""
        _write_template(templates_dir, 'emails/none.txt', 'Test')
        _write_template(templates_dir, 'emails/none.html', '<p>Test</p>')
        
        EmailService.send_email(
            subject='None CC/BCC',
            to=['recipient@example.com'],
            template_name='none',
            context={},
            cc=None,
            bcc=None,
        )
        
        assert len(mail.outbox) == 1
        msg = mail.outbox[0]
        assert msg.cc == []
        assert msg.bcc == []

    def test_send_email_none_attachments(self, templates_dir: Any) -> None:
        """Test that None attachments are handled correctly."""
        _write_template(templates_dir, 'emails/no_attach.txt', 'Test')
        _write_template(templates_dir, 'emails/no_attach.html', '<p>Test</p>')
        
        EmailService.send_email(
            subject='No Attachments',
            to=['recipient@example.com'],
            template_name='no_attach',
            context={},
            attachments=None,
        )
        
        assert len(mail.outbox) == 1
        assert len(mail.outbox[0].attachments) == 0

    @patch('util.email_service.EmailService.logger')
    def test_send_email_logs_info(self, mock_logger: Mock, templates_dir: Any) -> None:
        """Test that sending email logs an info message."""
        _write_template(templates_dir, 'emails/log.txt', 'Test')
        _write_template(templates_dir, 'emails/log.html', '<p>Test</p>')
        
        EmailService.send_email(
            subject='Log Test',
            to=['recipient@example.com'],
            template_name='log',
            context={},
        )
        
        mock_logger.info.assert_called_once()
        call_args = mock_logger.info.call_args[0]
        assert 'Sent email' in call_args[0]
        assert 'Log Test' in call_args[1]
        assert 'recipient@example.com' in call_args[2]

    @patch('util.email_service.EmailService.logger')
    def test_send_email_logs_multiple_recipients(self, mock_logger: Mock, templates_dir: Any) -> None:
        """Test that logging includes all recipients."""
        _write_template(templates_dir, 'emails/log_multi.txt', 'Test')
        _write_template(templates_dir, 'emails/log_multi.html', '<p>Test</p>')
        
        EmailService.send_email(
            subject='Multi Log',
            to=['r1@example.com', 'r2@example.com'],
            template_name='log_multi',
            context={},
        )
        
        mock_logger.info.assert_called_once()
        call_args = mock_logger.info.call_args[0]
        recipients_str = call_args[2]
        assert 'r1@example.com' in recipients_str
        assert 'r2@example.com' in recipients_str

    def test_send_email_template_rendering(self, templates_dir: Any) -> None:
        """Test that templates are rendered correctly with context."""
        _write_template(
            templates_dir,
            'emails/render.txt',
            'Plain: {{ var1 }} and {{ var2 }}'
        )
        _write_template(
            templates_dir,
            'emails/render.html',
            '<html><body>HTML: {{ var1 }} and {{ var2 }}</body></html>'
        )
        
        EmailService.send_email(
            subject='Rendering Test',
            to=['recipient@example.com'],
            template_name='render',
            context={'var1': 'Value1', 'var2': 'Value2'},
        )
        
        assert len(mail.outbox) == 1
        msg = mail.outbox[0]
        assert 'Plain: Value1 and Value2' in msg.body
        html_content = msg.alternatives[0][0]
        assert 'HTML: Value1 and Value2' in html_content

    def test_send_email_fail_silently_false(self, templates_dir: Any) -> None:
        """Test that send is called with fail_silently=False."""
        _write_template(templates_dir, 'emails/fail.txt', 'Test')
        _write_template(templates_dir, 'emails/fail.html', '<p>Test</p>')
        
        with patch.object(EmailMultiAlternatives, 'send') as mock_send:
            EmailService.send_email(
                subject='Fail Test',
                to=['recipient@example.com'],
                template_name='fail',
                context={},
            )
            
            mock_send.assert_called_once_with(fail_silently=False)

    def test_send_email_special_characters_in_subject(self, templates_dir: Any) -> None:
        """Test sending email with special characters in subject."""
        _write_template(templates_dir, 'emails/special.txt', 'Test')
        _write_template(templates_dir, 'emails/special.html', '<p>Test</p>')
        
        EmailService.send_email(
            subject='Test Äöü 日本語 🎉',
            to=['recipient@example.com'],
            template_name='special',
            context={},
        )
        
        assert len(mail.outbox) == 1
        assert mail.outbox[0].subject == 'Test Äöü 日本語 🎉'

    def test_send_email_unicode_in_templates(self, templates_dir: Any) -> None:
        """Test sending email with Unicode characters in templates."""
        _write_template(templates_dir, 'emails/unicode.txt', 'Ä ö ü ß 日本語 {{ name }}')
        _write_template(templates_dir, 'emails/unicode.html', '<p>Ä ö ü ß 日本語 {{ name }}</p>')
        
        EmailService.send_email(
            subject='Unicode Test',
            to=['recipient@example.com'],
            template_name='unicode',
            context={'name': '世界'},
        )
        
        assert len(mail.outbox) == 1
        msg = mail.outbox[0]
        assert 'Ä ö ü ß 日本語 世界' in msg.body
