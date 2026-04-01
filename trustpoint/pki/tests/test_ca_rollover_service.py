"""Tests for the CaRolloverService."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from pki.models.ca_rollover import CaRolloverModel, CaRolloverState, CaRolloverStrategyType
from pki.services.ca_rollover import CaRolloverError, CaRolloverService


class TestCaRolloverServicePlan:
    """Test CaRolloverService.plan_rollover."""

    def test_plan_rollover_import_ca(self, issuing_ca_model, second_issuing_ca_model):
        """Test planning a rollover with import_ca strategy."""
        # Ensure the import_ca strategy is registered
        import pki.rollover.import_ca  # noqa: F401

        form = MagicMock()
        form.is_valid.return_value = True
        form.cleaned_data = {
            'overlap_end': None,
            'notes': 'Test rollover',
        }
        form.new_issuing_ca = second_issuing_ca_model

        # Mock create_new_ca to return the new CA directly
        from pki.rollover.registry import rollover_registry

        strategy = rollover_registry.get(CaRolloverStrategyType.IMPORT_CA)
        original_create = strategy.create_new_ca
        strategy.create_new_ca = MagicMock(return_value=second_issuing_ca_model)

        try:
            rollover = CaRolloverService.plan_rollover(
                old_ca=issuing_ca_model,
                strategy_type=CaRolloverStrategyType.IMPORT_CA,
                form=form,
            )
            assert rollover.state == CaRolloverState.PLANNED
            assert rollover.old_issuing_ca == issuing_ca_model
            assert rollover.new_issuing_ca == second_issuing_ca_model
            assert rollover.strategy_type == CaRolloverStrategyType.IMPORT_CA
            assert rollover.notes == 'Test rollover'
        finally:
            strategy.create_new_ca = original_create

    def test_plan_rollover_prevents_duplicate(self, issuing_ca_model, second_issuing_ca_model):
        """Test that planning a second active rollover raises an error."""
        import pki.rollover.import_ca  # noqa: F401

        CaRolloverModel.objects.create(
            old_issuing_ca=issuing_ca_model,
            new_issuing_ca=second_issuing_ca_model,
            state=CaRolloverState.PLANNED,
            strategy_type=CaRolloverStrategyType.IMPORT_CA,
        )

        form = MagicMock()
        form.cleaned_data = {'overlap_end': None, 'notes': ''}

        with pytest.raises(CaRolloverError, match='already has an active rollover'):
            CaRolloverService.plan_rollover(
                old_ca=issuing_ca_model,
                strategy_type=CaRolloverStrategyType.IMPORT_CA,
                form=form,
            )

    def test_plan_rollover_blocked_after_completed(self, issuing_ca_model, second_issuing_ca_model):
        """Test that planning a rollover is blocked if a completed rollover exists."""
        import pki.rollover.import_ca  # noqa: F401

        rollover = CaRolloverModel.objects.create(
            old_issuing_ca=issuing_ca_model,
            new_issuing_ca=second_issuing_ca_model,
            state=CaRolloverState.PLANNED,
            strategy_type=CaRolloverStrategyType.IMPORT_CA,
        )
        rollover.start()
        rollover.complete()

        form = MagicMock()
        form.cleaned_data = {'overlap_end': None, 'notes': ''}

        with pytest.raises(CaRolloverError, match='has already been rolled over'):
            CaRolloverService.plan_rollover(
                old_ca=issuing_ca_model,
                strategy_type=CaRolloverStrategyType.IMPORT_CA,
                form=form,
            )


class TestCaRolloverServiceExecute:
    """Test CaRolloverService.execute_rollover."""

    def test_execute_rollover(self, issuing_ca_model, second_issuing_ca_model):
        """Test executing a planned rollover."""
        import pki.rollover.import_ca  # noqa: F401

        rollover = CaRolloverModel.objects.create(
            old_issuing_ca=issuing_ca_model,
            new_issuing_ca=second_issuing_ca_model,
            state=CaRolloverState.PLANNED,
            strategy_type=CaRolloverStrategyType.IMPORT_CA,
        )

        CaRolloverService.execute_rollover(rollover)
        rollover.refresh_from_db()
        assert rollover.state == CaRolloverState.IN_PROGRESS
        assert rollover.started_at is not None

    def test_execute_wrong_state(self, issuing_ca_model, second_issuing_ca_model):
        """Test that executing from IN_PROGRESS raises an error."""
        import pki.rollover.import_ca  # noqa: F401

        rollover = CaRolloverModel.objects.create(
            old_issuing_ca=issuing_ca_model,
            new_issuing_ca=second_issuing_ca_model,
            state=CaRolloverState.PLANNED,
            strategy_type=CaRolloverStrategyType.IMPORT_CA,
        )
        rollover.start()

        with pytest.raises(CaRolloverError):
            CaRolloverService.execute_rollover(rollover)


class TestCaRolloverServiceFinalize:
    """Test CaRolloverService.finalize_rollover."""

    def test_finalize_rollover(self, issuing_ca_model, second_issuing_ca_model):
        """Test finalizing an in-progress rollover."""
        import pki.rollover.import_ca  # noqa: F401

        rollover = CaRolloverModel.objects.create(
            old_issuing_ca=issuing_ca_model,
            new_issuing_ca=second_issuing_ca_model,
            state=CaRolloverState.PLANNED,
            strategy_type=CaRolloverStrategyType.IMPORT_CA,
        )
        rollover.start()

        CaRolloverService.finalize_rollover(rollover)
        rollover.refresh_from_db()
        assert rollover.state == CaRolloverState.COMPLETED

        # Import strategy deactivates old CA on complete
        issuing_ca_model.refresh_from_db()
        assert issuing_ca_model.is_active is False

    def test_finalize_rollover_reassigns_domains(self, issuing_ca_model, second_issuing_ca_model):
        """Test that finalizing a rollover reassigns domains from old CA to new CA."""
        import pki.rollover.import_ca  # noqa: F401

        from pki.models.domain import DomainModel

        domain = DomainModel.objects.create(
            unique_name='test_rollover_domain',
            issuing_ca=issuing_ca_model,
            is_active=True,
        )

        rollover = CaRolloverModel.objects.create(
            old_issuing_ca=issuing_ca_model,
            new_issuing_ca=second_issuing_ca_model,
            state=CaRolloverState.PLANNED,
            strategy_type=CaRolloverStrategyType.IMPORT_CA,
        )
        rollover.start()

        CaRolloverService.finalize_rollover(rollover)

        domain.refresh_from_db()
        assert domain.issuing_ca == second_issuing_ca_model

    def test_finalize_wrong_state(self, issuing_ca_model, second_issuing_ca_model):
        """Test that finalizing from PLANNED raises an error."""
        import pki.rollover.import_ca  # noqa: F401

        rollover = CaRolloverModel.objects.create(
            old_issuing_ca=issuing_ca_model,
            new_issuing_ca=second_issuing_ca_model,
            state=CaRolloverState.PLANNED,
            strategy_type=CaRolloverStrategyType.IMPORT_CA,
        )

        with pytest.raises(CaRolloverError):
            CaRolloverService.finalize_rollover(rollover)


class TestCaRolloverServiceCancel:
    """Test CaRolloverService.cancel_rollover."""

    def test_cancel_rollover(self, issuing_ca_model, second_issuing_ca_model):
        """Test cancelling a planned rollover."""
        import pki.rollover.import_ca  # noqa: F401

        rollover = CaRolloverModel.objects.create(
            old_issuing_ca=issuing_ca_model,
            new_issuing_ca=second_issuing_ca_model,
            state=CaRolloverState.PLANNED,
            strategy_type=CaRolloverStrategyType.IMPORT_CA,
        )

        CaRolloverService.cancel_rollover(rollover)
        rollover.refresh_from_db()
        assert rollover.state == CaRolloverState.CANCELLED

    def test_cancel_from_completed_raises(self, issuing_ca_model, second_issuing_ca_model):
        """Test that cancelling a completed rollover raises an error."""
        import pki.rollover.import_ca  # noqa: F401

        rollover = CaRolloverModel.objects.create(
            old_issuing_ca=issuing_ca_model,
            new_issuing_ca=second_issuing_ca_model,
            state=CaRolloverState.PLANNED,
            strategy_type=CaRolloverStrategyType.IMPORT_CA,
        )
        rollover.start()
        rollover.complete()

        with pytest.raises(CaRolloverError):
            CaRolloverService.cancel_rollover(rollover)


class TestCaRolloverServiceQueries:
    """Test CaRolloverService query methods."""

    def test_get_active_rollover(self, issuing_ca_model, second_issuing_ca_model):
        """Test retrieving the active rollover for a CA."""
        assert CaRolloverService.get_active_rollover(issuing_ca_model) is None

        rollover = CaRolloverModel.objects.create(
            old_issuing_ca=issuing_ca_model,
            new_issuing_ca=second_issuing_ca_model,
            state=CaRolloverState.PLANNED,
            strategy_type=CaRolloverStrategyType.IMPORT_CA,
        )

        active = CaRolloverService.get_active_rollover(issuing_ca_model)
        assert active is not None
        assert active.pk == rollover.pk

    def test_get_active_rollover_excludes_completed(self, issuing_ca_model, second_issuing_ca_model):
        """Test that completed rollovers are not returned as active."""
        rollover = CaRolloverModel.objects.create(
            old_issuing_ca=issuing_ca_model,
            new_issuing_ca=second_issuing_ca_model,
            state=CaRolloverState.PLANNED,
            strategy_type=CaRolloverStrategyType.IMPORT_CA,
        )
        rollover.start()
        rollover.complete()

        assert CaRolloverService.get_active_rollover(issuing_ca_model) is None

    def test_get_rollover_history(self, issuing_ca_model, second_issuing_ca_model):
        """Test retrieving rollover history for a CA."""
        rollover = CaRolloverModel.objects.create(
            old_issuing_ca=issuing_ca_model,
            new_issuing_ca=second_issuing_ca_model,
            state=CaRolloverState.PLANNED,
            strategy_type=CaRolloverStrategyType.IMPORT_CA,
        )
        rollover.start()
        rollover.complete()

        history = CaRolloverService.get_rollover_history(issuing_ca_model)
        assert history.count() == 1
        assert history.first().pk == rollover.pk

    def test_has_completed_rollover(self, issuing_ca_model, second_issuing_ca_model):
        """Test that has_completed_rollover returns True after a completed rollover."""
        assert CaRolloverService.has_completed_rollover(issuing_ca_model) is False

        rollover = CaRolloverModel.objects.create(
            old_issuing_ca=issuing_ca_model,
            new_issuing_ca=second_issuing_ca_model,
            state=CaRolloverState.PLANNED,
            strategy_type=CaRolloverStrategyType.IMPORT_CA,
        )
        rollover.start()
        rollover.complete()

        assert CaRolloverService.has_completed_rollover(issuing_ca_model) is True

    def test_has_completed_rollover_cancelled_does_not_count(self, issuing_ca_model, second_issuing_ca_model):
        """Test that a cancelled rollover does not count as completed."""
        rollover = CaRolloverModel.objects.create(
            old_issuing_ca=issuing_ca_model,
            new_issuing_ca=second_issuing_ca_model,
            state=CaRolloverState.PLANNED,
            strategy_type=CaRolloverStrategyType.IMPORT_CA,
        )
        rollover.cancel()

        assert CaRolloverService.has_completed_rollover(issuing_ca_model) is False


class TestCaRolloverServiceStrategy:
    """Test strategy resolution."""

    def test_get_available_strategies(self):
        """Test that at least the import strategy is available."""
        import pki.rollover.import_ca  # noqa: F401

        strategies = CaRolloverService.get_available_strategies()
        assert len(strategies) >= 1
        types = [s[0] for s in strategies]
        assert CaRolloverStrategyType.IMPORT_CA in types

    def test_get_unregistered_strategy_raises(self):
        """Test that getting an unregistered strategy raises an error."""
        # remote_ca is not registered by default
        with pytest.raises(CaRolloverError, match='No rollover strategy registered'):
            CaRolloverService.get_strategy(CaRolloverStrategyType.REMOTE_CA)
