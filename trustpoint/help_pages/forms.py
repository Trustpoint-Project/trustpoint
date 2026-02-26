"""Forms definition."""

from __future__ import annotations

from typing import Any, cast

from django import forms


class IpAddressForm(forms.Form):
    """The IP address selection Form."""

    host_ip = forms.ChoiceField(
        label='Update Host IP',
        required=True,
        choices=[],
        widget=forms.Select(
            attrs={
                'class': 'form-control form-select',
                'onchange': 'this.form.submit()'
            }
        )
    )

    def __init__(self, ip_choices:list[str], *args: Any, **kwargs: Any) -> None:
        """Initialize the IpAddressForm."""
        super().__init__(*args, **kwargs)
        if ip_choices:
            host_ip_field = cast('forms.ChoiceField', self.fields['host_ip'])
            host_ip_field.choices = [(ip, ip) for ip in ip_choices]
