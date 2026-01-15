"""Tests for forms module."""
from django import forms
from django.test import TestCase

from trustpoint.forms import DisableOptionsSelect


class TestDisableOptionsSelect(TestCase):
    """Test cases for DisableOptionsSelect widget."""

    def test_init_without_disabled_options(self) -> None:
        """Test initialization without disabled options."""
        widget = DisableOptionsSelect()
        assert widget.disabled_options == []

    def test_init_with_disabled_options(self) -> None:
        """Test initialization with disabled options."""
        disabled = ['option1', 'option2']
        widget = DisableOptionsSelect(disabled_options=disabled)
        assert widget.disabled_options == disabled

    def test_init_with_attrs(self) -> None:
        """Test initialization with HTML attributes."""
        attrs = {'class': 'custom-select'}
        widget = DisableOptionsSelect(attrs=attrs)
        assert widget.attrs == attrs

    def test_create_option_enabled(self) -> None:
        """Test creating an enabled option."""
        widget = DisableOptionsSelect(disabled_options=['disabled_value'])
        option = widget.create_option(
            name='test_field',
            value='enabled_value',
            label='Enabled Option',
            selected=False,
            index=0
        )
        assert 'disabled' not in option['attrs']

    def test_create_option_disabled(self) -> None:
        """Test creating a disabled option."""
        widget = DisableOptionsSelect(disabled_options=['disabled_value'])
        option = widget.create_option(
            name='test_field',
            value='disabled_value',
            label='Disabled Option',
            selected=False,
            index=0
        )
        assert option['attrs']['disabled'] == 'disabled'

    def test_create_option_with_subindex(self) -> None:
        """Test creating an option with subindex."""
        widget = DisableOptionsSelect(disabled_options=['disabled_value'])
        option = widget.create_option(
            name='test_field',
            value='test_value',
            label='Test Option',
            selected=True,
            index=0,
            subindex=1
        )
        assert 'disabled' not in option['attrs']

    def test_create_option_with_custom_attrs(self) -> None:
        """Test creating an option with custom attributes."""
        widget = DisableOptionsSelect(disabled_options=['disabled_value'])
        custom_attrs = {'data-custom': 'value'}
        option = widget.create_option(
            name='test_field',
            value='test_value',
            label='Test Option',
            selected=False,
            index=0,
            attrs=custom_attrs
        )
        assert 'disabled' not in option['attrs']

    def test_integration_with_form(self) -> None:
        """Test integration with a Django form."""
        class TestForm(forms.Form):
            choice_field = forms.ChoiceField(
                choices=[
                    ('enabled', 'Enabled'),
                    ('disabled', 'Disabled'),
                    ('also_disabled', 'Also Disabled'),
                ],
                widget=DisableOptionsSelect(
                    disabled_options=['disabled', 'also_disabled']
                )
            )

        form = TestForm()
        # Check that the widget is properly attached
        assert isinstance(form.fields['choice_field'].widget, DisableOptionsSelect)
        assert form.fields['choice_field'].widget.disabled_options == [
            'disabled', 'also_disabled'
        ]
