"""Tests for CRL cycle functionality."""

from __future__ import annotations

from datetime import datetime
from typing import Any

import pytest
from django.utils import timezone

from pki.models import CaModel
from pki.tasks import generate_crl_for_ca


@pytest.mark.django_db
def test_crl_cycle_enabled_flag(issuing_ca_instance: dict[str, Any]) -> None:
    """Test that CRL cycle can be enabled and disabled."""
    issuing_ca = issuing_ca_instance.get('issuing_ca')
    assert isinstance(issuing_ca, CaModel)

    # Initially, CRL cycle should be disabled
    assert issuing_ca.crl_cycle_enabled is False

    # Enable CRL cycle
    issuing_ca.crl_cycle_enabled = True
    issuing_ca.save()

    # Verify it's enabled
    issuing_ca.refresh_from_db()
    assert issuing_ca.crl_cycle_enabled is True


@pytest.mark.django_db
def test_crl_cycle_interval_hours_default(issuing_ca_instance: dict[str, Any]) -> None:
    """Test that CRL cycle interval has a default value."""
    issuing_ca = issuing_ca_instance.get('issuing_ca')
    assert isinstance(issuing_ca, CaModel)

    # Default should be 24 hours
    assert issuing_ca.crl_cycle_interval_hours == 24.0


@pytest.mark.django_db
def test_crl_validity_hours_default(issuing_ca_instance: dict[str, Any]) -> None:
    """Test that CRL validity hours has a default value."""
    issuing_ca = issuing_ca_instance.get('issuing_ca')
    assert isinstance(issuing_ca, CaModel)

    # Default should be 24 hours
    assert issuing_ca.crl_validity_hours == 24.0


@pytest.mark.django_db
def test_crl_validity_hours_custom_value(issuing_ca_instance: dict[str, Any]) -> None:
    """Test that CRL validity hours can be set to a custom value."""
    issuing_ca = issuing_ca_instance.get('issuing_ca')
    assert isinstance(issuing_ca, CaModel)

    # Set custom validity
    issuing_ca.crl_validity_hours = 48.0
    issuing_ca.save()

    issuing_ca.refresh_from_db()
    assert issuing_ca.crl_validity_hours == 48.0


@pytest.mark.django_db
def test_crl_cycle_interval_validation_minimum(issuing_ca_instance: dict[str, Any]) -> None:
    """Test that CRL cycle interval has a minimum value."""
    issuing_ca = issuing_ca_instance.get('issuing_ca')
    assert isinstance(issuing_ca, CaModel)

    from pki.models.ca import MIN_CRL_CYCLE_INTERVAL_HOURS
    from django.core.exceptions import ValidationError

    issuing_ca.crl_cycle_enabled = True
    issuing_ca.crl_cycle_interval_hours = MIN_CRL_CYCLE_INTERVAL_HOURS - 0.01

    with pytest.raises(ValidationError):
        issuing_ca.full_clean()


@pytest.mark.django_db
def test_schedule_next_crl_generation(issuing_ca_instance: dict[str, Any]) -> None:
    """Test that scheduling CRL generation works."""
    issuing_ca = issuing_ca_instance.get('issuing_ca')
    assert isinstance(issuing_ca, CaModel)

    issuing_ca.crl_cycle_enabled = True
    issuing_ca.crl_cycle_interval_hours = 24.0
    issuing_ca.save()

    # Schedule next CRL generation
    issuing_ca.schedule_next_crl_generation()

    issuing_ca.refresh_from_db()
    assert issuing_ca.last_crl_generation_started_at is not None

    # Verify the scheduled time is approximately 24 hours in the future
    now = timezone.now()
    scheduled_time = issuing_ca.last_crl_generation_started_at
    time_diff = (scheduled_time - now).total_seconds()

    # Should be close to 24 hours (86400 seconds), with some tolerance
    assert 86300 < time_diff < 86500


@pytest.mark.django_db
def test_schedule_next_crl_generation_disabled(issuing_ca_instance: dict[str, Any]) -> None:
    """Test that scheduling is skipped when CRL cycle is disabled."""
    issuing_ca = issuing_ca_instance.get('issuing_ca')
    assert isinstance(issuing_ca, CaModel)

    issuing_ca.crl_cycle_enabled = False
    issuing_ca.save()

    # Try to schedule
    issuing_ca.schedule_next_crl_generation()

    issuing_ca.refresh_from_db()
    # Should not be scheduled
    assert issuing_ca.last_crl_generation_started_at is None


@pytest.mark.django_db
def test_generate_crl_for_ca_task(issuing_ca_instance: dict[str, Any]) -> None:
    """Test that the generate_crl_for_ca task works correctly."""
    issuing_ca = issuing_ca_instance.get('issuing_ca')
    assert isinstance(issuing_ca, CaModel)

    issuing_ca.crl_validity_hours = 48.0
    issuing_ca.save()

    # Execute the task
    generate_crl_for_ca(issuing_ca.id)

    # Verify CRL was generated
    issuing_ca.refresh_from_db()
    assert issuing_ca.last_crl_issued_at is not None
    assert issuing_ca.crl_pem != ''


@pytest.mark.django_db
def test_generate_crl_for_ca_task_invalid_ca() -> None:
    """Test that the task handles invalid CA ID gracefully."""
    with pytest.raises(ValueError):
        generate_crl_for_ca(99999)


@pytest.mark.django_db
def test_generate_crl_uses_configured_validity(issuing_ca_instance: dict[str, Any]) -> None:
    """Test that generated CRL respects the configured validity hours."""
    issuing_ca = issuing_ca_instance.get('issuing_ca')
    priv_key = issuing_ca_instance.get('priv_key')
    assert isinstance(issuing_ca, CaModel)

    issuing_ca.crl_validity_hours = 72.0
    issuing_ca.save()

    # Generate CRL
    issuing_ca.issue_crl(crl_validity_hours=int(issuing_ca.crl_validity_hours))

    # Parse the CRL to verify nextUpdate
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend

    crl_object = x509.load_pem_x509_crl(
        str.encode(issuing_ca.crl_pem),
        default_backend()
    )

    # Check that nextUpdate is approximately 72 hours after thisUpdate
    this_update = crl_object.last_update_utc
    next_update = crl_object.next_update_utc

    assert next_update is not None

    time_diff_seconds = (next_update - this_update).total_seconds()
    expected_seconds = 72 * 3600  # 72 hours in seconds

    # Allow 60 second tolerance
    assert abs(time_diff_seconds - expected_seconds) < 60


@pytest.mark.django_db
def test_next_crl_generation_scheduled_at_property(issuing_ca_instance: dict[str, Any]) -> None:
    """Test the next_crl_generation_scheduled_at property."""
    issuing_ca = issuing_ca_instance.get('issuing_ca')
    assert isinstance(issuing_ca, CaModel)

    # When disabled, should return None
    issuing_ca.crl_cycle_enabled = False
    issuing_ca.save()
    assert issuing_ca.next_crl_generation_scheduled_at is None

    # When enabled but not scheduled yet
    issuing_ca.crl_cycle_enabled = True
    issuing_ca.save()
    assert issuing_ca.next_crl_generation_scheduled_at is None

    # Schedule a generation
    issuing_ca.schedule_next_crl_generation()
    issuing_ca.refresh_from_db()

    # Should return the scheduled time
    assert issuing_ca.next_crl_generation_scheduled_at is not None
    assert isinstance(issuing_ca.next_crl_generation_scheduled_at, datetime)


@pytest.mark.django_db
def test_crl_cycle_custom_intervals(issuing_ca_instance: dict[str, Any]) -> None:
    """Test various custom CRL cycle intervals."""
    issuing_ca = issuing_ca_instance.get('issuing_ca')
    assert isinstance(issuing_ca, CaModel)

    test_intervals = [0.5, 1.0, 6.0, 12.0, 24.0, 48.0, 168.0]

    for interval in test_intervals:
        issuing_ca.crl_cycle_enabled = True
        issuing_ca.crl_cycle_interval_hours = interval
        # Set validity period to be at least as large as the interval
        issuing_ca.crl_validity_hours = max(interval, 24.0)
        issuing_ca.save()
        issuing_ca.full_clean()  # Should not raise

        issuing_ca.schedule_next_crl_generation()
        issuing_ca.refresh_from_db()

        now = timezone.now()
        scheduled_time = issuing_ca.last_crl_generation_started_at

        assert scheduled_time is not None

        # Verify scheduled time is approximately interval hours in future
        expected_seconds = interval * 3600
        actual_seconds = (scheduled_time - now).total_seconds()

        # Allow 60 second tolerance
        assert abs(actual_seconds - expected_seconds) < 60
