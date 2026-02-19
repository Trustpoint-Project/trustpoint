"""Tests for CRL cycle view functionality."""

from __future__ import annotations

from typing import Any

import pytest
from django.contrib.auth.models import User
from django.test import Client
from django.urls import reverse

from pki.models import CaModel


@pytest.fixture
def admin_user() -> User:
    """Create an admin user for testing."""
    user = User.objects.create_superuser(
        username='admin',
        email='admin@test.com',
        password='testpass123'
    )
    return user


@pytest.fixture
def client_with_auth(admin_user: User) -> Client:
    """Create a client with authenticated user."""
    client = Client()
    client.force_login(admin_user)
    return client


@pytest.mark.django_db
def test_generate_crl_view_uses_configured_validity(
    issuing_ca_instance: dict[str, Any],
    client_with_auth: Client
) -> None:
    """Test that GenerateCrlView uses the configured CRL validity."""
    issuing_ca: CaModel = issuing_ca_instance.get('issuing_ca')  # type: ignore[assignment]

    # Set custom validity
    issuing_ca.crl_validity_hours = 72.0
    issuing_ca.save()

    # Generate CRL via view
    url = reverse('pki:issuing_cas-crl-gen', kwargs={'pk': issuing_ca.pk})
    response = client_with_auth.get(url)

    # Should redirect back to config page
    assert response.status_code == 302

    # Verify CRL was generated with correct validity
    issuing_ca.refresh_from_db()
    assert issuing_ca.crl_pem != ''

    from cryptography import x509
    from cryptography.hazmat.backends import default_backend

    crl_object = x509.load_pem_x509_crl(
        str.encode(issuing_ca.crl_pem),
        default_backend()
    )

    this_update = crl_object.last_update_utc
    next_update = crl_object.next_update_utc

    assert next_update is not None
    time_diff_seconds = (next_update - this_update).total_seconds()
    expected_seconds = 72 * 3600

    # Allow 60 second tolerance
    assert abs(time_diff_seconds - expected_seconds) < 60


@pytest.mark.django_db
def test_generate_crl_view_default_validity(
    issuing_ca_instance: dict[str, Any],
    client_with_auth: Client
) -> None:
    """Test that GenerateCrlView uses default validity when not set."""
    issuing_ca: CaModel = issuing_ca_instance.get('issuing_ca')  # type: ignore[assignment]

    # Should use default 24 hours
    assert issuing_ca.crl_validity_hours == 24.0

    # Generate CRL via view
    url = reverse('pki:issuing_cas-crl-gen', kwargs={'pk': issuing_ca.pk})
    response = client_with_auth.get(url)

    assert response.status_code == 302

    issuing_ca.refresh_from_db()
    assert issuing_ca.crl_pem != ''


@pytest.mark.django_db
def test_ca_config_view_loads_crl_settings(
    issuing_ca_instance: dict[str, Any],
    client_with_auth: Client
) -> None:
    """Test that CA config view loads CRL cycle settings."""
    issuing_ca: CaModel = issuing_ca_instance.get('issuing_ca')  # type: ignore[assignment]

    url = reverse('pki:issuing_cas-config', kwargs={'pk': issuing_ca.pk})
    response = client_with_auth.get(url)

    assert response.status_code == 200
    assert b'CRL Configuration' in response.content or b'crl' in response.content.lower()


@pytest.mark.django_db
def test_ca_config_view_save_crl_settings(
    issuing_ca_instance: dict[str, Any],
    client_with_auth: Client
) -> None:
    """Test that CA config view saves CRL cycle settings."""
    issuing_ca: CaModel = issuing_ca_instance.get('issuing_ca')  # type: ignore[assignment]

    url = reverse('pki:issuing_cas-config', kwargs={'pk': issuing_ca.pk})

    form_data = {
        'crl_cycle_enabled': 'on',
        'crl_cycle_interval_hours': 48.0,
        'crl_validity_hours': 72.0,
    }

    response = client_with_auth.post(url, data=form_data)

    # Should redirect or stay on page
    assert response.status_code in [200, 302]

    # Verify settings were saved
    issuing_ca.refresh_from_db()
    assert issuing_ca.crl_cycle_enabled is True
    assert issuing_ca.crl_cycle_interval_hours == 48.0
    assert issuing_ca.crl_validity_hours == 72.0
