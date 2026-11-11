# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Tests for the user's certificate-authentication profile page."""

from __future__ import annotations

import datetime as dt

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from django.contrib.auth import get_user_model
from django.test import Client
from django.urls import reverse

from pki.models import CertificateModel
from users.models import UserClientCertificate

pytestmark = pytest.mark.django_db


def test_client_certificate_list_links_to_certificate_details() -> None:
    """Each issued client certificate exposes a link to its certificate details."""
    user = get_user_model().objects.create_user(username='cert-owner')
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'trustpoint-client-certificate')])
    now = dt.datetime.now(dt.UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(days=30))
        .sign(key, hashes.SHA256())
    )
    certificate_model = CertificateModel.save_certificate(certificate)
    UserClientCertificate.objects.create(
        user=user,
        certificate=certificate_model,
        identifier='laptop',
    )

    client = Client()
    client.force_login(user)
    response = client.get(reverse('users:profile_certificate_authentication'))

    assert response.status_code == 200  # noqa: PLR2004
    assert reverse('pki:certificate-detail', kwargs={'pk': certificate_model.pk}) in response.content.decode()
