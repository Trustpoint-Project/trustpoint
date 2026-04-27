"""Generate keypair rollover strategy — stub for future implementation."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pki.models.ca_rollover import CaRolloverStrategyType
from pki.rollover.base import RolloverStrategy

if TYPE_CHECKING:
    from django import forms

    from pki.models import CaModel


class GenerateKeypairRolloverStrategy(RolloverStrategy):
    """Rollover strategy: generate a new keypair and request a signed certificate.

    NOT YET IMPLEMENTED — this is a stub to ensure the architecture supports
    future extension without modifying existing code.

    Flow:
    1. Plan: Generate keypair + CSR
    2. AWAITING_NEW_CA: Operator downloads CSR, gets it signed externally, uploads signed cert
    3. IN_PROGRESS: New CA is active
    """

    @property
    def strategy_type(self) -> CaRolloverStrategyType:
        """Return the strategy type identifier."""
        return CaRolloverStrategyType.GENERATE_KEYPAIR

    @property
    def display_name(self) -> str:
        """Return a human-readable strategy name."""
        return 'Generate keypair and request certificate'

    def get_plan_form(
        self,
        old_ca: CaModel,
        data: dict[str, object] | None = None,
        files: dict[str, object] | None = None,
    ) -> forms.Form:
        """Return the form for configuring key generation parameters.

        :raises NotImplementedError: Strategy not yet implemented.
        """
        msg = 'GenerateKeypairRolloverStrategy is not yet implemented.'
        raise NotImplementedError(msg)

    def create_new_ca(self, form: forms.Form, old_ca: CaModel) -> CaModel | None:
        """Generate keypair and CSR — returns None (async provisioning).

        :raises NotImplementedError: Strategy not yet implemented.
        """
        msg = 'GenerateKeypairRolloverStrategy is not yet implemented.'
        raise NotImplementedError(msg)

    def get_template_name(self) -> str:
        """Return the template for generate-keypair-specific form fields."""
        return 'pki/issuing_cas/includes/rollover_generate_keypair_fields.html'

