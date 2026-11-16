# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""User client certificates share the configured certificate expiry checks."""

from datetime import timedelta
from io import StringIO

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from django.core.management import call_command
from django.utils import timezone

from management.models import NotificationConfig, NotificationModel
from pki.models import CertificateModel
from users.models import TrustpointUser, UserClientCertificate

pytestmark = pytest.mark.django_db


@pytest.fixture
def certificate():
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'trustpoint-client-certificate')])
    now = timezone.now()
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=90))
        .not_valid_after(now + timedelta(days=90))
        .sign(key, hashes.SHA256())
    )
    model = CertificateModel.save_certificate(cert)
    UserClientCertificate.objects.create(
        user=TrustpointUser.objects.create_user(username='cert-owner'),
        certificate=model,
        identifier='laptop',
    )
    return model


@pytest.mark.parametrize(
    ('days_remaining', 'warning_days', 'message_type', 'severity'),
    [
        (5, 7, 'USER_CERT_EXPIRING', 'WAR'),
        (5, 3, None, None),
        (7, 7, 'USER_CERT_EXPIRING', 'WAR'),
        (-1, 0, 'USER_CERT_EXPIRED', 'CRI'),
        (0, 7, 'USER_CERT_EXPIRED', 'CRI'),
        (1, 0, None, None),
    ],
)
def test_user_certificate_expiry(certificate, monkeypatch, days_remaining, warning_days, message_type, severity):
    now = certificate.not_valid_after - timedelta(days=days_remaining)
    monkeypatch.setattr('management.management.commands.check_certificate_validity.timezone.now', lambda: now)
    config = NotificationConfig.get()
    config.cert_expiry_warning_days = warning_days
    config.save()

    for _ in range(2):
        call_command('check_certificate_validity', stdout=StringIO())

    notifications = NotificationModel.objects.filter(certificate=certificate)
    if message_type is None:
        assert not notifications.exists()
        return
    notification = notifications.get()
    assert notification.message_type == message_type
    assert notification.notification_type == severity
    assert notification.notification_source == NotificationModel.NotificationSource.CERTIFICATE
    assert notification.statuses.filter(status='NEW').exists()
    assert 'laptop' in notification.short_translated
    assert 'cert-owner' in notification.short_translated
    assert certificate.not_valid_after.strftime('%Y-%m-%d %H:%M:%S') in notification.long_translated


def test_generic_certificate_notifications_are_preserved(certificate, monkeypatch):
    UserClientCertificate.objects.all().delete()
    now = certificate.not_valid_after + timedelta(days=1)
    monkeypatch.setattr('management.management.commands.check_certificate_validity.timezone.now', lambda: now)

    call_command('check_certificate_validity', stdout=StringIO())

    notification = NotificationModel.objects.get(certificate=certificate)
    assert notification.message_type == NotificationModel.NotificationMessageType.CERT_EXPIRED


def test_user_certificate_notification_escapes_user_input(certificate, monkeypatch):
    from django.template import Context, Template

    association = certificate.user_client_certificate
    association.identifier = '<script>alert(1)</script>'
    association.save()
    now = certificate.not_valid_after + timedelta(days=1)
    monkeypatch.setattr('management.management.commands.check_certificate_validity.timezone.now', lambda: now)

    call_command('check_certificate_validity', stdout=StringIO())

    notification = NotificationModel.objects.get(certificate=certificate)
    assert '<script>' not in notification.long_translated
    assert '&lt;script&gt;' in notification.long_translated
    assert notification.message_data['identifier'] == association.identifier
    title = Template('{{ notification.short_translated }}').render(Context({'notification': notification}))
    assert '&lt;script&gt;' in title
    assert '&amp;lt;' not in title
