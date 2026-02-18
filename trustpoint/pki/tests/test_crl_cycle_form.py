"""Tests for CRL cycle form functionality."""

from __future__ import annotations

from typing import Any

import pytest
from django.core.exceptions import ValidationError

from pki.forms.issuing_cas import IssuingCaCrlCycleForm
from pki.models import CaModel
from pki.models.ca import MIN_CRL_CYCLE_INTERVAL_HOURS


@pytest.mark.django_db
def test_crl_cycle_form_valid(issuing_ca_instance: dict[str, Any]) -> None:
    """Test that the CRL cycle form validates correctly."""
    issuing_ca = issuing_ca_instance.get('issuing_ca')

    form_data = {
        'crl_cycle_enabled': True,
        'crl_cycle_interval_hours': 24.0,
        'crl_validity_hours': 48.0,
    }

    form = IssuingCaCrlCycleForm(data=form_data, instance=issuing_ca)
    assert form.is_valid()


@pytest.mark.django_db
def test_crl_cycle_form_disabled(issuing_ca_instance: dict[str, Any]) -> None:
    """Test that the CRL cycle form works when disabled."""
    issuing_ca = issuing_ca_instance.get('issuing_ca')

    form_data = {
        'crl_cycle_enabled': False,
        'crl_cycle_interval_hours': 24.0,
        'crl_validity_hours': 48.0,
    }

    form = IssuingCaCrlCycleForm(data=form_data, instance=issuing_ca)
    assert form.is_valid()


@pytest.mark.django_db
def test_crl_cycle_form_invalid_interval_too_small(issuing_ca_instance: dict[str, Any]) -> None:
    """Test that the form rejects intervals smaller than minimum."""
    issuing_ca = issuing_ca_instance.get('issuing_ca')

    form_data = {
        'crl_cycle_enabled': True,
        'crl_cycle_interval_hours': MIN_CRL_CYCLE_INTERVAL_HOURS - 0.01,
        'crl_validity_hours': 24.0,
    }

    form = IssuingCaCrlCycleForm(data=form_data, instance=issuing_ca)
    assert not form.is_valid()
    assert 'crl_cycle_interval_hours' in form.errors


@pytest.mark.django_db
def test_crl_cycle_form_minimum_interval_valid(issuing_ca_instance: dict[str, Any]) -> None:
    """Test that the form accepts the minimum interval."""
    issuing_ca = issuing_ca_instance.get('issuing_ca')

    form_data = {
        'crl_cycle_enabled': True,
        'crl_cycle_interval_hours': MIN_CRL_CYCLE_INTERVAL_HOURS,
        'crl_validity_hours': 24.0,
    }

    form = IssuingCaCrlCycleForm(data=form_data, instance=issuing_ca)
    assert form.is_valid()


@pytest.mark.django_db
def test_crl_cycle_form_various_validity_values(issuing_ca_instance: dict[str, Any]) -> None:
    """Test that various validity hour values are accepted."""
    issuing_ca = issuing_ca_instance.get('issuing_ca')

    test_values = [1.0, 6.0, 12.0, 24.0, 48.0, 72.0, 168.0]

    for validity in test_values:
        form_data = {
            'crl_cycle_enabled': True,
            'crl_cycle_interval_hours': 24.0,
            'crl_validity_hours': validity,
        }

        form = IssuingCaCrlCycleForm(data=form_data, instance=issuing_ca)
        assert form.is_valid(), f"Form should be valid for validity={validity}"


@pytest.mark.django_db
def test_crl_cycle_form_save_schedules_generation(issuing_ca_instance: dict[str, Any]) -> None:
    """Test that saving the form with cycle enabled schedules CRL generation."""
    issuing_ca: CaModel = issuing_ca_instance.get('issuing_ca')  # type: ignore[assignment]

    form_data = {
        'crl_cycle_enabled': True,
        'crl_cycle_interval_hours': 24.0,
        'crl_validity_hours': 48.0,
    }

    form = IssuingCaCrlCycleForm(data=form_data, instance=issuing_ca)
    assert form.is_valid()

    # Save the form
    saved_ca = form.save()

    # Verify scheduling happened
    assert saved_ca.last_crl_generation_started_at is not None


@pytest.mark.django_db
def test_crl_cycle_form_save_disabled_no_scheduling(issuing_ca_instance: dict[str, Any]) -> None:
    """Test that saving with cycle disabled doesn't schedule."""
    issuing_ca: CaModel = issuing_ca_instance.get('issuing_ca')  # type: ignore[assignment]

    # First enable it
    issuing_ca.crl_cycle_enabled = True
    issuing_ca.save()
    issuing_ca.schedule_next_crl_generation()
    old_scheduled = issuing_ca.last_crl_generation_started_at

    # Now disable it via form
    form_data = {
        'crl_cycle_enabled': False,
        'crl_cycle_interval_hours': 24.0,
        'crl_validity_hours': 48.0,
    }

    form = IssuingCaCrlCycleForm(data=form_data, instance=issuing_ca)
    assert form.is_valid()
    saved_ca = form.save()

    # Scheduled time should not change
    assert saved_ca.last_crl_generation_started_at == old_scheduled


@pytest.mark.django_db
def test_crl_cycle_form_fields_present(issuing_ca_instance: dict[str, Any]) -> None:
    """Test that the form has all required fields."""
    issuing_ca = issuing_ca_instance.get('issuing_ca')

    form = IssuingCaCrlCycleForm(instance=issuing_ca)

    # Check that all required fields are present
    assert 'crl_cycle_enabled' in form.fields
    assert 'crl_cycle_interval_hours' in form.fields
    assert 'crl_validity_hours' in form.fields


@pytest.mark.django_db
def test_crl_cycle_form_field_labels(issuing_ca_instance: dict[str, Any]) -> None:
    """Test that form fields have proper labels."""
    issuing_ca = issuing_ca_instance.get('issuing_ca')

    form = IssuingCaCrlCycleForm(instance=issuing_ca)

    assert 'Enable CRL Cycle Updates' in str(form.fields['crl_cycle_enabled'].label)
    assert 'CRL Cycle Interval' in str(form.fields['crl_cycle_interval_hours'].label)
    assert 'CRL Validity' in str(form.fields['crl_validity_hours'].label)
