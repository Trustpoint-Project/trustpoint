"""Tests for CA rollover background tasks."""

from __future__ import annotations

from datetime import timedelta
from unittest.mock import patch

import pytest
from django.utils import timezone

from pki.models.ca_rollover import CaRolloverModel, CaRolloverState, CaRolloverStrategyType
from pki.tasks import check_rollover_transition


class TestCheckRolloverTransition:
    """Test the check_rollover_transition background task."""

    @pytest.fixture
    def rollover_in_preparation(self, issuing_ca_model, second_issuing_ca_model):
        """Create a rollover in PREPARATION state."""
        rollover = CaRolloverModel.objects.create(
            old_issuing_ca=issuing_ca_model,
            new_issuing_ca=second_issuing_ca_model,
            state=CaRolloverState.PLANNED,
            strategy_type=CaRolloverStrategyType.IMPORT_CA,
        )
        rollover.start()
        return rollover

    def test_transition_when_time_reached(self, rollover_in_preparation):
        """Test that the task transitions the rollover when scheduled time is reached."""
        # Set transition time to the past
        rollover_in_preparation.transition_scheduled_at = timezone.now() - timedelta(hours=1)
        rollover_in_preparation.save()

        # Run the task
        check_rollover_transition(rollover_in_preparation.id)

        # Reload from database
        rollover_in_preparation.refresh_from_db()

        # Should be in TRANSITION state now
        assert rollover_in_preparation.state == CaRolloverState.TRANSITION

    def test_no_transition_when_time_not_reached(self, rollover_in_preparation):
        """Test that the task does not transition when scheduled time is in the future."""
        # Set transition time to the future
        rollover_in_preparation.transition_scheduled_at = timezone.now() + timedelta(hours=1)
        rollover_in_preparation.save()

        # Run the task
        check_rollover_transition(rollover_in_preparation.id)

        # Reload from database
        rollover_in_preparation.refresh_from_db()

        # Should still be in PREPARATION state
        assert rollover_in_preparation.state == CaRolloverState.PREPARATION

    def test_no_transition_when_no_time_set(self, rollover_in_preparation):
        """Test that the task does not transition when no scheduled time is set."""
        # Ensure no transition time is set
        rollover_in_preparation.transition_scheduled_at = None
        rollover_in_preparation.save()

        # Run the task
        check_rollover_transition(rollover_in_preparation.id)

        # Reload from database
        rollover_in_preparation.refresh_from_db()

        # Should still be in PREPARATION state
        assert rollover_in_preparation.state == CaRolloverState.PREPARATION

    def test_no_transition_when_not_in_preparation(self, issuing_ca_model, second_issuing_ca_model):
        """Test that the task does not transition when rollover is not in PREPARATION state."""
        # Create a rollover in PLANNED state
        rollover = CaRolloverModel.objects.create(
            old_issuing_ca=issuing_ca_model,
            new_issuing_ca=second_issuing_ca_model,
            state=CaRolloverState.PLANNED,
            strategy_type=CaRolloverStrategyType.IMPORT_CA,
            transition_scheduled_at=timezone.now() - timedelta(hours=1),
        )

        # Run the task
        check_rollover_transition(rollover.id)

        # Reload from database
        rollover.refresh_from_db()

        # Should still be in PLANNED state
        assert rollover.state == CaRolloverState.PLANNED

    def test_raises_error_when_rollover_not_found(self):
        """Test that the task raises an error when rollover does not exist."""
        with pytest.raises(ValueError, match='CA Rollover with ID 99999 does not exist'):
            check_rollover_transition(99999)


class TestScheduleTransitionCheck:
    """Test the schedule_transition_check method on CaRolloverModel."""

    @pytest.fixture
    def rollover_in_preparation(self, issuing_ca_model, second_issuing_ca_model):
        """Create a rollover in PREPARATION state."""
        rollover = CaRolloverModel.objects.create(
            old_issuing_ca=issuing_ca_model,
            new_issuing_ca=second_issuing_ca_model,
            state=CaRolloverState.PLANNED,
            strategy_type=CaRolloverStrategyType.IMPORT_CA,
        )
        rollover.start()
        return rollover

    @patch('pki.models.ca_rollover.schedule')
    @patch('pki.models.ca_rollover.Schedule')
    def test_schedule_with_specific_time(self, mock_schedule_model, mock_schedule, rollover_in_preparation):
        """Test scheduling a transition check with a specific time."""
        transition_time = timezone.now() + timedelta(days=7)
        rollover_in_preparation.transition_scheduled_at = transition_time
        rollover_in_preparation.save()

        # Call the scheduling method
        rollover_in_preparation.schedule_transition_check()

        # Verify schedule was called with the correct parameters
        mock_schedule.assert_called_once()
        call_args = mock_schedule.call_args
        assert call_args[0][0] == 'pki.tasks.check_rollover_transition'
        assert call_args[0][1] == rollover_in_preparation.id
        assert call_args[1]['schedule_type'] == 'O'
        assert call_args[1]['next_run'] == transition_time

    @patch('pki.models.ca_rollover.schedule')
    @patch('pki.models.ca_rollover.Schedule')
    def test_schedule_without_specific_time(self, mock_schedule_model, mock_schedule, rollover_in_preparation):
        """Test scheduling a periodic transition check when no specific time is set."""
        rollover_in_preparation.transition_scheduled_at = None
        rollover_in_preparation.save()

        # Call the scheduling method
        rollover_in_preparation.schedule_transition_check()

        # Verify schedule was called
        mock_schedule.assert_called_once()
        call_args = mock_schedule.call_args
        assert call_args[0][0] == 'pki.tasks.check_rollover_transition'
        assert call_args[0][1] == rollover_in_preparation.id
        assert call_args[1]['schedule_type'] == 'O'

    @patch('pki.models.ca_rollover.schedule')
    @patch('pki.models.ca_rollover.Schedule')
    def test_no_schedule_when_not_in_preparation(
        self, mock_schedule_model, mock_schedule, issuing_ca_model, second_issuing_ca_model
    ):
        """Test that no scheduling happens when rollover is not in PREPARATION state."""
        rollover = CaRolloverModel.objects.create(
            old_issuing_ca=issuing_ca_model,
            new_issuing_ca=second_issuing_ca_model,
            state=CaRolloverState.PLANNED,
            strategy_type=CaRolloverStrategyType.IMPORT_CA,
        )

        # Call the scheduling method
        rollover.schedule_transition_check()

        # Verify schedule was NOT called
        mock_schedule.assert_not_called()
