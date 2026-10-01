# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Generate-keypair rollover strategy using the normal EST/CMP forms."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from django import forms
from django.utils.translation import gettext_lazy as _

from pki.forms.issuing_cas import IssuingCaAddRequestCmpForm, IssuingCaAddRequestEstForm
from pki.models.ca_rollover import CaRolloverStrategyType
from pki.rollover.base import RolloverStrategy
from pki.rollover.registry import rollover_registry

if TYPE_CHECKING:
    from collections.abc import Mapping

    from django.core.files.uploadedfile import UploadedFile
    from django.utils.datastructures import MultiValueDict

    from pki.models import CaModel


class GenerateKeypairRolloverStrategy(RolloverStrategy):
    """Rollover strategy: generate a new keypair and request a signed certificate.

    The normal request forms generate the managed key and retain the editable
    upstream connection/authentication settings. The existing request views can
    then obtain the certificate for the pending replacement CA.
    """

    @property
    def strategy_type(self) -> CaRolloverStrategyType:
        """Return the strategy type identifier."""
        return CaRolloverStrategyType.GENERATE_KEYPAIR

    @property
    def display_name(self) -> str:
        """Return a human-readable strategy name."""
        return 'Generate keypair and request certificate'

    @property
    def awaits_new_ca_certificate(self) -> bool:
        """Keep the provisional request CA awaiting its EST/CMP certificate."""
        return True

    def get_plan_form(
        self,
        old_ca: CaModel,
        data: Mapping[str, object] | None = None,
        files: MultiValueDict[str, UploadedFile[Any]] | None = None,
    ) -> forms.Form:
        """Return the form for configuring key generation parameters.

        :raises NotImplementedError: Strategy not yet implemented.
        """
        msg = 'Select EST or CMP before creating this form.'
        raise NotImplementedError(msg)

    def create_new_ca(self, form: forms.Form, old_ca: CaModel) -> CaModel | None:
        """Generate keypair and CSR — returns None (async provisioning).

        :raises NotImplementedError: Strategy not yet implemented.
        """
        _ = old_ca
        if not isinstance(form, (GenerateKeypairEstRolloverForm, GenerateKeypairCmpRolloverForm)):
            msg = 'Expected a generated-keypair rollover form.'
            raise TypeError(msg)
        return form.save()

    def get_template_name(self) -> str:
        """Return the template for generate-keypair-specific form fields."""
        return 'pki/issuing_cas/includes/rollover_generate_keypair_fields.html'

    def on_complete(self, rollover: Any) -> None:
        """Apply the same domain/activation transition as imported CAs."""
        old_ca = rollover.old_issuing_ca
        new_ca = rollover.new_issuing_ca
        if new_ca is not None:
            old_ca.domains.update(issuing_ca=new_ca)
        old_ca.is_active = False
        old_ca.save(update_fields=['is_active'])


class GenerateKeypairEstRolloverForm(IssuingCaAddRequestEstForm):
    """Normal EST request form with rollover scheduling metadata."""

    transition_scheduled_at = forms.DateTimeField(
        required=False,
        label=_('Scheduled Transition Time'),
        widget=forms.DateTimeInput(attrs={'type': 'datetime-local', 'class': 'form-control'}),
    )
    notes = forms.CharField(required=False, label=_('Notes'), widget=forms.Textarea(attrs={'rows': 3}))


class GenerateKeypairCmpRolloverForm(IssuingCaAddRequestCmpForm):
    """Normal CMP request form with rollover scheduling metadata."""

    transition_scheduled_at = forms.DateTimeField(
        required=False,
        label=_('Scheduled Transition Time'),
        widget=forms.DateTimeInput(attrs={'type': 'datetime-local', 'class': 'form-control'}),
    )
    notes = forms.CharField(required=False, label=_('Notes'), widget=forms.Textarea(attrs={'rows': 3}))


rollover_registry.register(GenerateKeypairRolloverStrategy())

