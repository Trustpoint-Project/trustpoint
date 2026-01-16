"""Filter form and parsed filter values for the unified workflow request list.

This module provides:
- A Django form (`UnifiedRequestFilterForm`) used to validate GET query parameters.
- An immutable dataclass (`UnifiedRequestFilters`) that normalizes cleaned form data
  into a simple, typed container consumed by views/query builders.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from django import forms
from django.utils.translation import gettext_lazy as _

from pki.models import DomainModel
from workflows.models import State


class UnifiedRequestFilterForm(forms.Form):
    """Django form for filtering unified enrollment/device request listings."""
    device_name = forms.CharField(
        label=_('Device'),
        required=False,
        widget=forms.TextInput(
            attrs={'class': 'form-control form-control-sm', 'placeholder': _('Search device…')}
        ),
    )

    domain = forms.ModelChoiceField(
        label=_('Domain'),
        required=False,
        queryset=DomainModel.objects.all(),
        widget=forms.Select(attrs={'class': 'form-select form-select-sm'}),
    )

    type = forms.ChoiceField(
        label=_('Type'),
        required=False,
        choices=(
            ('', _('All')),
            ('Enrollment', _('Enrollment')),
            ('Device', _('Device Event')),
        ),
        widget=forms.Select(attrs={'class': 'form-select form-select-sm'}),
    )

    state = forms.ChoiceField(
        label=_('State'),
        required=False,
        choices=(('', _('All')), *State.choices),
        widget=forms.Select(attrs={'class': 'form-select form-select-sm'}),
    )

    include_finalized = forms.BooleanField(
        label=_('Include finalized/aborted requests'),
        required=False,
        widget=forms.CheckboxInput(attrs={'class': 'form-check-input'}),
    )

    protocol = forms.CharField(
        label=_('Protocol'),
        required=False,
        widget=forms.TextInput(
            attrs={'class': 'form-control form-control-sm', 'placeholder': _('EST, CMP, …')}
        ),
    )

    # Unified: "operation" is the single field.
    # For EnrollmentRequest it maps to operation; for DeviceRequest it maps to action.
    operation = forms.CharField(
        label=_('Operation'),
        required=False,
        widget=forms.TextInput(
            attrs={'class': 'form-control form-control-sm', 'placeholder': _('simpleenroll, created, domain changed, …')}
        ),
    )

    template = forms.CharField(
        label=_('Template'),
        required=False,
        widget=forms.TextInput(
            attrs={'class': 'form-control form-control-sm', 'placeholder': _('tls_client, …')}
        ),
    )

    requested_from = forms.DateTimeField(
        label=_('Requested from'),
        required=False,
        widget=forms.DateTimeInput(attrs={'type': 'datetime-local', 'class': 'form-control form-control-sm'}),
    )

    requested_to = forms.DateTimeField(
        label=_('Requested to'),
        required=False,
        widget=forms.DateTimeInput(attrs={'type': 'datetime-local', 'class': 'form-control form-control-sm'}),
    )


@dataclass(frozen=True)
class UnifiedRequestFilters:
    """Normalized filter values derived from `UnifiedRequestFilterForm`.

    Attributes:
        device_name: Substring filter applied to device common name.
        domain_id: Optional domain primary key.
        type: Request type discriminator ("Enrollment", "Device", or "").
        state: Aggregated state filter or "" for all.
        include_finalized: Whether to include finalized/aborted requests.
        protocol: Protocol substring (Enrollment only; Device rows use "device").
        operation: Operation/action substring.
        template: Template substring (Enrollment only).
        requested_from: Optional lower bound for created_at.
        requested_to: Optional upper bound for created_at.
    """
    device_name: str
    domain_id: int | None
    type: str
    state: str
    include_finalized: bool
    protocol: str
    operation: str
    template: str
    requested_from: Any
    requested_to: Any

    @classmethod
    def from_form(cls, form: UnifiedRequestFilterForm) -> UnifiedRequestFilters:
        """Create normalized filters from a validated form.

        Args:
            form: A bound `UnifiedRequestFilterForm`. The caller is expected to have
                called `is_valid()` before invoking this method.

        Returns:
            A `UnifiedRequestFilters` instance containing normalized filter values.
        """
        cd = form.cleaned_data
        dom = cd.get('domain')
        return cls(
            device_name=str(cd.get('device_name') or '').strip(),
            domain_id=int(dom.id) if dom is not None else None,
            type=str(cd.get('type') or ''),
            state=str(cd.get('state') or ''),
            include_finalized=bool(cd.get('include_finalized') or False),
            protocol=str(cd.get('protocol') or '').strip(),
            operation=str(cd.get('operation') or '').strip(),
            template=str(cd.get('template') or '').strip(),
            requested_from=cd.get('requested_from'),
            requested_to=cd.get('requested_to'),
        )
