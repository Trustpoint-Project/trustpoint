"""Tests for CRL cycle signal functionality."""

from __future__ import annotations

from typing import Any

import pytest
from django.utils import timezone

from pki.models import CaModel


@pytest.mark.django_db
def test_schedule_next_crl_after_generation_signal(issuing_ca_instance: dict[str, Any]) -> None:
    """Test that CRL generation schedules the next one automatically."""
    issuing_ca: CaModel = issuing_ca_instance.get('issuing_ca')  # type: ignore[assignment]

    # Enable CRL cycle
    issuing_ca.crl_cycle_enabled = True
    issuing_ca.crl_cycle_interval_hours = 24.0
    issuing_ca.save()

    # Clear any previous scheduling
    issuing_ca.last_crl_generation_started_at = None
    issuing_ca.save()

    # Generate a CRL (which triggers the signal)
    issuing_ca.issue_crl()

    issuing_ca.refresh_from_db()

    # The signal should have scheduled the next generation
    assert issuing_ca.last_crl_generation_started_at is not None

    # Verify it's scheduled for approximately 24 hours in the future
    now = timezone.now()
    scheduled_time = issuing_ca.last_crl_generation_started_at
    time_diff = (scheduled_time - now).total_seconds()

    # Should be close to 24 hours (86400 seconds)
    assert 86200 < time_diff < 86600


@pytest.mark.django_db
def test_schedule_next_crl_after_generation_signal_disabled(issuing_ca_instance: dict[str, Any]) -> None:
    """Test that signal respects disabled CRL cycle."""
    issuing_ca: CaModel = issuing_ca_instance.get('issuing_ca')  # type: ignore[assignment]

    # Ensure CRL cycle is disabled
    issuing_ca.crl_cycle_enabled = False
    issuing_ca.save()

    # Clear scheduling
    issuing_ca.last_crl_generation_started_at = None
    issuing_ca.save()

    # Generate a CRL
    issuing_ca.issue_crl()

    issuing_ca.refresh_from_db()

    # Should NOT schedule next generation
    assert issuing_ca.last_crl_generation_started_at is None


@pytest.mark.django_db
def test_schedule_crl_on_cycle_enable_signal(issuing_ca_instance: dict[str, Any]) -> None:
    """Test that enabling CRL cycle schedules the first generation."""
    issuing_ca: CaModel = issuing_ca_instance.get('issuing_ca')  # type: ignore[assignment]

    # Ensure disabled initially
    issuing_ca.crl_cycle_enabled = False
    issuing_ca.last_crl_generation_started_at = None
    issuing_ca.save()

    # Now enable it via update (which triggers the signal)
    issuing_ca.crl_cycle_enabled = True
    issuing_ca.crl_cycle_interval_hours = 24.0
    issuing_ca.save(update_fields=['crl_cycle_enabled', 'crl_cycle_interval_hours'])

    issuing_ca.refresh_from_db()

    # Signal should have scheduled the first generation
    assert issuing_ca.last_crl_generation_started_at is not None


@pytest.mark.django_db
def test_schedule_crl_on_cycle_enable_respects_false_to_false(issuing_ca_instance: dict[str, Any]) -> None:
    """Test that signal doesn't schedule when toggling from false to false."""
    issuing_ca: CaModel = issuing_ca_instance.get('issuing_ca')  # type: ignore[assignment]

    issuing_ca.crl_cycle_enabled = False
    issuing_ca.last_crl_generation_started_at = None
    issuing_ca.save()

    # Update other field while keeping cycle disabled
    issuing_ca.crl_cycle_interval_hours = 48.0
    issuing_ca.save(update_fields=['crl_cycle_interval_hours'])

    issuing_ca.refresh_from_db()

    # Should not schedule when toggling to False
    assert issuing_ca.last_crl_generation_started_at is None


@pytest.mark.django_db
def test_schedule_crl_on_cycle_enable_multiple_toggles(issuing_ca_instance: dict[str, Any]) -> None:
    """Test signal behavior with multiple enable/disable cycles."""
    issuing_ca: CaModel = issuing_ca_instance.get('issuing_ca')  # type: ignore[assignment]

    issuing_ca.crl_cycle_enabled = False
    issuing_ca.last_crl_generation_started_at = None
    issuing_ca.save()

    # Enable
    issuing_ca.crl_cycle_enabled = True
    issuing_ca.save(update_fields=['crl_cycle_enabled'])
    issuing_ca.refresh_from_db()
    first_scheduled = issuing_ca.last_crl_generation_started_at
    assert first_scheduled is not None

    # Disable
    issuing_ca.crl_cycle_enabled = False
    issuing_ca.save(update_fields=['crl_cycle_enabled'])
    issuing_ca.refresh_from_db()

    # Enable again
    issuing_ca.crl_cycle_enabled = True
    issuing_ca.save(update_fields=['crl_cycle_enabled'])
    issuing_ca.refresh_from_db()
    second_scheduled = issuing_ca.last_crl_generation_started_at

    # New scheduling should have been created
    assert second_scheduled is not None
    # The times might be the same or very close, but both should be scheduled
    assert second_scheduled >= first_scheduled
