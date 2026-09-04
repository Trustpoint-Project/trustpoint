"""Tests for rollover strategy contracts, including not-yet-implemented paths."""

from __future__ import annotations

import pytest

from pki.models.ca_rollover import CaRolloverStrategyType
from pki.rollover.generate_keypair import GenerateKeypairRolloverStrategy
from pki.rollover.remote_ca import RemoteCaRolloverStrategy


@pytest.mark.parametrize(
    'strategy, strategy_type, template',
    [
        (
            GenerateKeypairRolloverStrategy(),
            CaRolloverStrategyType.GENERATE_KEYPAIR,
            'pki/issuing_cas/includes/rollover_generate_keypair_fields.html',
        ),
        (
            RemoteCaRolloverStrategy(),
            CaRolloverStrategyType.REMOTE_CA,
            'pki/issuing_cas/includes/rollover_remote_ca_fields.html',
        ),
    ],
)
def test_strategy_metadata_is_stable(strategy, strategy_type, template) -> None:
    """Each strategy exposes stable registry metadata and a template."""
    assert strategy.strategy_type == strategy_type
    assert strategy.display_name
    assert strategy.get_template_name() == template


@pytest.mark.parametrize('strategy', [GenerateKeypairRolloverStrategy(), RemoteCaRolloverStrategy()])
def test_unimplemented_strategy_operations_fail_explicitly(strategy, issuing_ca_model) -> None:
    """Stub operations fail explicitly until their workflows are implemented."""
    with pytest.raises(NotImplementedError, match='not yet implemented'):
        strategy.get_plan_form(issuing_ca_model)
    with pytest.raises(NotImplementedError, match='not yet implemented'):
        strategy.create_new_ca(object(), issuing_ca_model)
