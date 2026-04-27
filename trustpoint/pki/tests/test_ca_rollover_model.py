"""Tests for the CaRolloverModel."""

from __future__ import annotations

import pytest
from django.db import IntegrityError
from django.utils import timezone

from pki.models.ca_rollover import CaRolloverModel, CaRolloverState, CaRolloverStrategyType


class TestCaRolloverModelStates:
    """Test state transitions on CaRolloverModel."""

    @pytest.fixture()
    def _rollover(self, issuing_ca_model, second_issuing_ca_model):
        """Create a basic rollover in PLANNED state."""
        return CaRolloverModel.objects.create(
            old_issuing_ca=issuing_ca_model,
            new_issuing_ca=second_issuing_ca_model,
            state=CaRolloverState.PLANNED,
            strategy_type=CaRolloverStrategyType.IMPORT_CA,
        )

    def test_start_from_planned(self, _rollover):
        """Test starting a rollover from PLANNED state."""
        _rollover.start()
        _rollover.refresh_from_db()
        assert _rollover.state == CaRolloverState.IN_PROGRESS
        assert _rollover.started_at is not None

    def test_start_requires_new_ca(self, issuing_ca_model):
        """Test that starting fails if new_issuing_ca is None."""
        rollover = CaRolloverModel.objects.create(
            old_issuing_ca=issuing_ca_model,
            new_issuing_ca=None,
            state=CaRolloverState.PLANNED,
            strategy_type=CaRolloverStrategyType.IMPORT_CA,
        )
        with pytest.raises(ValueError, match='Cannot start rollover without a new Issuing CA'):
            rollover.start()

    def test_start_from_wrong_state(self, _rollover):
        """Test that start from IN_PROGRESS raises."""
        _rollover.start()
        with pytest.raises(ValueError, match='Cannot start rollover'):
            _rollover.start()

    def test_complete_from_in_progress(self, _rollover):
        """Test completing a rollover from IN_PROGRESS state."""
        _rollover.start()
        _rollover.complete()
        _rollover.refresh_from_db()
        assert _rollover.state == CaRolloverState.COMPLETED
        assert _rollover.completed_at is not None

    def test_complete_from_wrong_state(self, _rollover):
        """Test that complete from PLANNED raises."""
        with pytest.raises(ValueError, match='Cannot complete rollover'):
            _rollover.complete()

    def test_cancel_from_planned(self, _rollover):
        """Test cancelling from PLANNED state."""
        _rollover.cancel()
        _rollover.refresh_from_db()
        assert _rollover.state == CaRolloverState.CANCELLED

    def test_cancel_from_in_progress(self, _rollover):
        """Test cancelling from IN_PROGRESS state."""
        _rollover.start()
        _rollover.cancel()
        _rollover.refresh_from_db()
        assert _rollover.state == CaRolloverState.CANCELLED

    def test_cancel_from_completed_raises(self, _rollover):
        """Test that cancel from COMPLETED raises."""
        _rollover.start()
        _rollover.complete()
        with pytest.raises(ValueError, match='Cannot cancel rollover'):
            _rollover.cancel()

    def test_cancel_from_cancelled_raises(self, _rollover):
        """Test that cancel from CANCELLED raises."""
        _rollover.cancel()
        with pytest.raises(ValueError, match='Cannot cancel rollover'):
            _rollover.cancel()

    def test_is_active_property(self, _rollover):
        """Test the is_active property in various states."""
        assert _rollover.is_active is True

        _rollover.start()
        assert _rollover.is_active is True

        _rollover.complete()
        assert _rollover.is_active is False

    def test_overlap_has_ended_no_date(self, _rollover):
        """Test overlap_has_ended when no overlap_end is set."""
        assert _rollover.overlap_has_ended is False

    def test_overlap_has_ended_future(self, _rollover):
        """Test overlap_has_ended when overlap_end is in the future."""
        from datetime import timedelta
        _rollover.overlap_end = timezone.now() + timedelta(days=30)
        _rollover.save()
        assert _rollover.overlap_has_ended is False

    def test_overlap_has_ended_past(self, _rollover):
        """Test overlap_has_ended when overlap_end is in the past."""
        from datetime import timedelta
        _rollover.overlap_end = timezone.now() - timedelta(days=1)
        _rollover.save()
        assert _rollover.overlap_has_ended is True

    def test_str_representation(self, _rollover):
        """Test string representation includes both CAs and state."""
        result = str(_rollover)
        assert '→' in result
        assert 'Planned' in result


class TestCaRolloverModelConstraints:
    """Test database constraints on CaRolloverModel."""

    def test_unique_active_rollover_per_old_ca(self, issuing_ca_model, second_issuing_ca_model):
        """Test that only one active rollover per old CA is allowed."""
        CaRolloverModel.objects.create(
            old_issuing_ca=issuing_ca_model,
            new_issuing_ca=second_issuing_ca_model,
            state=CaRolloverState.PLANNED,
            strategy_type=CaRolloverStrategyType.IMPORT_CA,
        )

        with pytest.raises(IntegrityError):
            CaRolloverModel.objects.create(
                old_issuing_ca=issuing_ca_model,
                new_issuing_ca=second_issuing_ca_model,
                state=CaRolloverState.IN_PROGRESS,
                strategy_type=CaRolloverStrategyType.IMPORT_CA,
            )

    def test_completed_rollover_allows_new_one_at_db_level(self, issuing_ca_model, second_issuing_ca_model):
        """Test that the DB constraint allows a new rollover after completion.

        The business rule preventing a second rollover is enforced at the service layer,
        not at the database level. The DB only prevents multiple *active* rollovers.
        """
        rollover = CaRolloverModel.objects.create(
            old_issuing_ca=issuing_ca_model,
            new_issuing_ca=second_issuing_ca_model,
            state=CaRolloverState.PLANNED,
            strategy_type=CaRolloverStrategyType.IMPORT_CA,
        )
        rollover.start()
        rollover.complete()

        # DB constraint does not block this; the service layer does.
        new_rollover = CaRolloverModel.objects.create(
            old_issuing_ca=issuing_ca_model,
            new_issuing_ca=second_issuing_ca_model,
            state=CaRolloverState.PLANNED,
            strategy_type=CaRolloverStrategyType.IMPORT_CA,
        )
        assert new_rollover.pk is not None
