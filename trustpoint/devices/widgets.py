from typing import Any
from django import forms
from typing import TypeAlias

_OptAttrs: TypeAlias = dict[str, Any]

class DisableSelectOptionsWidget(forms.Select):

    disabled_values: list[str]

    def __init__(self, disabled_values: list[str]=[''], *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.disabled_values = disabled_values

    def create_option(self, name: str, value: Any, label: int | str, selected: bool, index: int, subindex: int | None = None, attrs: _OptAttrs | None=None) -> dict[str, Any]:
        option_dict = super().create_option(name, value, label, selected, index, subindex, attrs)
        if value in self.disabled_values:
            option_dict['attrs'].setdefault('disabled', 'disabled')

        return option_dict
