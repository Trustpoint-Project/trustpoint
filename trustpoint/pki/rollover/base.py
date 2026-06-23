"""Abstract base class for CA rollover strategies."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Mapping

    from django import forms
    from django.core.files.uploadedfile import UploadedFile
    from django.utils.datastructures import MultiValueDict

    from pki.models import CaModel
    from pki.models.ca_rollover import CaRolloverModel, CaRolloverStrategyType


class RolloverStrategy(ABC):
    """Abstract base for CA rollover strategies."""

    @property
    @abstractmethod
    def strategy_type(self) -> CaRolloverStrategyType:
        """Return the strategy type identifier stored on the rollover model."""

    @property
    @abstractmethod
    def display_name(self) -> str:
        """Return a human-readable name for this strategy."""

    @abstractmethod
    def get_plan_form(
        self,
        old_ca: CaModel,
        data: Mapping[str, object] | None = None,
        files: MultiValueDict[str, UploadedFile] | None = None,
    ) -> forms.Form:
        """Return the form used to plan a rollover with this strategy."""

    @abstractmethod
    def create_new_ca(self, form: forms.Form, old_ca: CaModel) -> CaModel | None:
        """Create the new Issuing CA from the validated form data."""

    def get_awaiting_form(
        self,
        rollover: CaRolloverModel,  # noqa: ARG002
        data: Mapping[str, object] | None = None,  # noqa: ARG002
        files: MultiValueDict[str, UploadedFile] | None = None,  # noqa: ARG002
    ) -> forms.Form | None:
        """Return a form for the AWAITING_NEW_CA state, if applicable."""
        return None

    def provide_new_ca(self, rollover: CaRolloverModel, form: forms.Form) -> CaModel:
        """Provide the new CA from the awaiting form."""
        msg = f'Strategy {self.strategy_type} does not support provide_new_ca.'
        raise NotImplementedError(msg)

    def on_start(self, rollover: CaRolloverModel) -> None:
        """Hook called when a rollover transitions to PREPARATION."""
        _ = rollover

    def on_complete(self, rollover: CaRolloverModel) -> None:
        """Hook called when a rollover is finalized."""
        _ = rollover

    def on_cancel(self, rollover: CaRolloverModel) -> None:
        """Hook called when a rollover is cancelled."""
        _ = rollover

    @abstractmethod
    def get_template_name(self) -> str:
        """Return the template name for the strategy-specific form fields."""
