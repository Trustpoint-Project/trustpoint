"""Forms used by the Workflow 2 definition editor."""

from __future__ import annotations

from django import forms
from django.utils.translation import gettext_lazy as _


class Workflow2DefinitionForm(forms.Form):
    """Edit one Workflow 2 definition as YAML plus a small amount of metadata."""

    name = forms.CharField(
        max_length=200,
        required=True,
        label=_('Name'),
        widget=forms.TextInput(attrs={'class': 'form-control'}),
    )
    enabled = forms.BooleanField(
        required=False,
        initial=True,
        label=_('Enabled'),
        widget=forms.CheckboxInput(attrs={'class': 'form-check-input'}),
    )
    yaml_text = forms.CharField(
        required=True,
        label=_('YAML'),
        widget=forms.Textarea(
            attrs={
                'class': 'form-control font-monospace',
                'rows': 26,
                'spellcheck': 'false',
                'style': 'white-space: pre; tab-size: 2;',
            }
        ),
        help_text=_('YAML workflow definition (v2).'),
    )
