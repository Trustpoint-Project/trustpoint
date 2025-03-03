"""This module contains widgets used in the devices app."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Any

from django import forms


class DisableSelectOptionsWidget(forms.Select):
    """Allows to disable options within a select input."""

    disabled_values: list[str]

    def __init__(self, disabled_values: list[str] | None = None, *args: Any, **kwargs: Any) -> None:
        """Initializes the DisableSelectOptionsWidget.

        Args:
            disabled_values: The values to disable.
            *args: Positional arguments passed to forms.Select.
            **kwargs: Keyword arguments passed to forms.Select.
        """
        super().__init__(*args, **kwargs)
        if disabled_values is None:
            self.disabled_values = []
        else:
            self.disabled_values = disabled_values

    def create_option(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
        """Creates the options in the select and disables the desired ones.

        Args:
            *args: Positional arguments passed to forms.Select.create_option.
            **kwargs: Positional arguments passed to forms.Select.create_option.

        Returns:
            The option dictionary.
        """
        value = kwargs.get('value')
        option_dict = super().create_option(*args, **kwargs)
        if value in self.disabled_values:
            option_dict['attrs'].setdefault('disabled', 'disabled')

        return option_dict
