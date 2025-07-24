# workflows/forms.py

from __future__ import annotations

from typing import Any, Dict, List, Optional
from uuid import UUID

from django import forms
from django.forms import BaseFormSet, formset_factory

from workflows.models import WorkflowDefinition, WorkflowScope
from workflows.triggers import Triggers


class TriggerForm(forms.Form):
    """Single trigger: pick a protocol, then an operation."""
    protocol  = forms.ChoiceField(label='Protocol')
    operation = forms.ChoiceField(label='Operation')

    def __init__(
        self,
        *args: Any,
        initial: Optional[Dict[str, Any]] = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(*args, initial=initial or {}, **kwargs)

        # 1) protocol choices from Triggers.protocols()
        proto_choices = [(p, p) for p in Triggers.protocols()]
        self.fields['protocol'].choices = proto_choices

        # 2) determine selected protocol (POSTed or initial)
        data = self.data or {}
        selected = (
            data.get(self.add_prefix('protocol'))
            or self.initial.get('protocol')
            or proto_choices[0][0]
        )

        # 3) operation choices from Triggers.operations_for(selected)
        ops: List[str] = Triggers.operations_for(selected)
        self.fields['operation'].choices = [(op, op) for op in ops]


class BaseTriggerFormSet(BaseFormSet):
    """Ensure at least one trigger is defined."""
    def clean(self) -> None:
        super().clean()
        if any(self.errors):
            return
        if len(self.forms) < 1:
            raise forms.ValidationError('At least one trigger is required.')


TriggerFormSet = formset_factory(
    TriggerForm,
    formset=BaseTriggerFormSet,
    extra=1,
    can_delete=True,
)


class NodeForm(forms.Form):
    """Single node: id, type, parameters (as JSON)."""
    NODE_TYPE_CHOICES = [
        ('Approval', 'Approval'),
        ('IssueCertificate', 'Issue Certificate'),
        ('Condition', 'Condition'),
        ('Email', 'Email'),
        ('Webhook', 'Webhook'),
        ('Timer', 'Timer'),
    ]

    node_id = forms.CharField(
        max_length=100,
        label='Node ID',
        help_text='Unique identifier for this step',
    )
    node_type = forms.ChoiceField(
        choices=NODE_TYPE_CHOICES,
        label='Type',
    )
    params = forms.CharField(
        widget=forms.Textarea(attrs={'rows': 3}),
        required=False,
        label='Parameters (JSON)',
        help_text='Optional JSON object for node parameters',
    )


NodeFormSet = formset_factory(
    NodeForm,
    extra=2,
    can_delete=True,
)


class TransitionForm(forms.Form):
    """Single transition: from → (on) → to."""
    from_node = forms.CharField(
        max_length=100,
        label='From Node ID',
    )
    on_signal = forms.CharField(
        max_length=50,
        label='On Signal',
        help_text='e.g. "Approved", "Rejected"',
    )
    to_node = forms.CharField(
        max_length=100,
        label='To Node ID',
    )


TransitionFormSet = formset_factory(
    TransitionForm,
    extra=1,
    can_delete=True,
)


class ScopeForm(forms.Form):
    """Assign workflow to CA / domain / device."""
    ca_id = forms.UUIDField(
        required=False,
        label='CA UUID',
        help_text='Leave blank to match any CA',
    )
    domain_id = forms.UUIDField(
        required=False,
        label='Domain UUID',
        help_text='Leave blank to match any domain',
    )
    device_id = forms.UUIDField(
        required=False,
        label='Device UUID',
        help_text='Leave blank to match any device',
    )


ScopeFormSet = formset_factory(
    ScopeForm,
    extra=1,
    can_delete=True,
)
