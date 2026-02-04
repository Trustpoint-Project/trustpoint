from __future__ import annotations

from django import forms


class Workflow2DefinitionForm(forms.Form):
    name = forms.CharField(
        max_length=200,
        required=True,
        widget=forms.TextInput(attrs={"class": "form-control"}),
    )
    enabled = forms.BooleanField(
        required=False,
        initial=True,
        widget=forms.CheckboxInput(attrs={"class": "form-check-input"}),
    )
    yaml_text = forms.CharField(
        required=True,
        widget=forms.Textarea(
            attrs={
                "class": "form-control font-monospace",
                "rows": 26,
                "spellcheck": "false",
                "style": "white-space: pre; tab-size: 2;",
            }
        ),
        help_text="YAML workflow definition (v2).",
    )
