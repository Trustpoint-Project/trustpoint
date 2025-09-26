"""Module containing the form to create UserToken instances."""
from datetime import timedelta
from typing import ClassVar

from django import forms
from django.utils import timezone

from .models import UserToken


class UserTokenForm(forms.ModelForm):
    """Form for creating and updating UserToken instances with an expiration date."""
    expires_at = forms.DateTimeField(
        widget=forms.DateTimeInput(attrs={'type': 'datetime-local'}), initial=timezone.now() + timedelta(days=7)
    )

    class Meta:
        """Metadata for UserTokenForm."""
        model: ClassVar[type] = UserToken
        fields: ClassVar[list[str]] = ['expires_at']