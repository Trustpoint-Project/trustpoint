"""This module provides utility methods for forms in the overall project."""

from __future__ import annotations

from typing import TYPE_CHECKING

from django import forms

if TYPE_CHECKING:
    from typing import Any

    from django.forms import BaseForm

    _TypingForm = BaseForm
else:
    _TypingForm = object


class CleanedDataNotNoneMixin(_TypingForm):
    """Mixin to ensure that `cleaned_data` is never `None` after form validation."""

    def clean(self) -> dict[str, Any]:
        """Cleans and validates form data, ensuring `cleaned_data` is not `None`."""
        cleaned_data = super().clean()
        if cleaned_data is None:
            err_msg = 'Failed to get cleaned form data.'
            raise forms.ValidationError(err_msg)
        return cleaned_data
