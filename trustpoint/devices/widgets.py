from django import forms

class DisableSelectOptionsWidget(forms.Select):

    def __init__(self, disabled_values=None, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.disabled_values = disabled_values

    def create_option(self, name, value, label, selected, index, subindex=None, attrs=None) -> dict:
        option_dict = super().create_option(name, value, label, selected, index, subindex, attrs)
        if value in self.disabled_values:
            option_dict['attrs'].setdefault('disabled', 'disabled')

        return option_dict
