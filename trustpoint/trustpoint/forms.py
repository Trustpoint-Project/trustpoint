"""Contains classes and helpers for forms that can be used in the whole project."""

from typing import Any

from django import forms


class DisableOptionsSelect(forms.Select):
    """A custom Select widget that allows disabling specific optionsm in a Django ChoiceField dropdown.

    Example usage:
        forms.ChoiceField(
            choices=...,
            widget=DisableOptionsSelect(disabled_options=['some_value'])
        )
    """
    def __init__(
        self,
        attrs: dict[str, Any] | None = None,
        disabled_options: list[Any] | None = None,
    ) -> None:
        """Initialize the widget.

        Args:
            attrs: Optional dictionary of HTML attributes.
            disabled_options: List of option values that should be disabled.
        """
        self.disabled_options = disabled_options or []
        super().__init__(attrs)

    def create_option(  # noqa: PLR0913
        self,
        name: str,
        value: Any,
        label: int | str,
        selected: bool,  # noqa: FBT001
        index: int,
        subindex: int | None = None,
        attrs: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Create a single option dictionary for rendering.

        Overrides the default method to add the `disabled` attribute
        for options whose value is in `self.disabled_options`.

        Args:
            name: Name of the form field.
            value: Value of the option.
            label: Display label for the option.
            selected: Whether the option is selected.
            index: Index of the option.
            subindex: Optional subindex for optgroups.
            attrs: Additional HTML attributes.

        Returns:
            A dictionary representing the option to render.
        """
        option_dict = super().create_option(
            name, value, label, selected, index, subindex=subindex, attrs=attrs
        )

        if value in self.disabled_options:
            option_dict['attrs']['disabled'] = 'disabled'

        return option_dict
