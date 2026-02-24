"""Forms definition."""

from __future__ import annotations

from django import forms


class IpAddressForm(forms.Form):
    """The IP address selection Form."""

    host_ip = forms.GenericIPAddressField(
        label='Host IP',
        required=True,
        protocol='IPv4',
        widget=forms.TextInput(
            attrs={
                'class': 'form-control',
                'placeholder': '127.0.0.1'
            }
        )
    )
