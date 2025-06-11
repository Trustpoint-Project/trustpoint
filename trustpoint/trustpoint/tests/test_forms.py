"""Tests for the forms module."""

from typing import Any

import pytest
from django import forms

from trustpoint.forms import CleanedDataNotNoneMixin


class DummyForm(CleanedDataNotNoneMixin, forms.Form):
    field = forms.CharField(required=True)

@pytest.mark.django_db
class TestCleanedDataNotNoneMixin:
    """Test cases for CleanedDataNotNoneMixin."""

    def test_clean_returns_cleaned_data(self) -> None:
        """Verify clean method returns valid cleaned_data."""
        data = {'field': 'test'}
        form = DummyForm(data=data)
        assert form.is_valid()
        cleaned_data = form.clean()
        assert isinstance(cleaned_data, dict)
        assert cleaned_data['field'] == 'test'

    def test_clean_raises_error_for_empty_data(self) -> None:
        """Check clean raises ValidationError if data is invalid."""

        class TestForm(DummyForm):
            def clean(self) -> dict[str, Any]:
                # Simulate super().clean() returning None
                self.cleaned_data = None
                return super().clean()

        form = TestForm(data={})
        with pytest.raises(forms.ValidationError, match='Failed to get cleaned form data.'):
            form.clean()
