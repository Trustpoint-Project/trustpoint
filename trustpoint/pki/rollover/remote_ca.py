"""Remote CA rollover strategy — stub for future implementation."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pki.models.ca_rollover import CaRolloverStrategyType
from pki.rollover.base import RolloverStrategy

if TYPE_CHECKING:
    from collections.abc import Mapping

    from django import forms
    from django.core.files.uploadedfile import UploadedFile
    from django.utils.datastructures import MultiValueDict

    from pki.models import CaModel


class RemoteCaRolloverStrategy(RolloverStrategy):
    """Rollover strategy: request a new Issuing CA certificate from a remote CA.

    Flow:
    1. Plan: Configure remote CA endpoint (URL, auth)
    2. AWAITING_NEW_CA: Initiate CMP/EST request to upstream CA
    3. PREPARATION: New CA added to truststores, old CA still issues
    4. TRANSITION: New CA issues, old CA still in truststore
    """

    @property
    def strategy_type(self) -> CaRolloverStrategyType:
        """Return the strategy type identifier."""
        return CaRolloverStrategyType.REMOTE_CA

    @property
    def display_name(self) -> str:
        """Return a human-readable strategy name."""
        return 'Configure a remote Issuing CA'

    def get_plan_form(
        self,
        old_ca: CaModel,
        data: Mapping[str, object] | None = None,
        files: MultiValueDict[str, UploadedFile] | None = None,
    ) -> forms.Form:
        """Return the form for configuring remote CA endpoint."""
        msg = 'RemoteCaRolloverStrategy is not yet implemented.'
        raise NotImplementedError(msg)

    def create_new_ca(self, form: forms.Form, old_ca: CaModel) -> CaModel | None:
        """Initiate remote request — returns None (async provisioning)."""
        msg = 'RemoteCaRolloverStrategy is not yet implemented.'
        raise NotImplementedError(msg)

    def get_template_name(self) -> str:
        """Return the template for remote-CA-specific form fields."""
        return 'pki/issuing_cas/includes/rollover_remote_ca_fields.html'
