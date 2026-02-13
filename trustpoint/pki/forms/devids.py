"""Django forms for DevID registration and management."""

from __future__ import annotations

from typing import Any, ClassVar

from django import forms
from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _

from pki.models import DevIdRegistration
from util.field import UniqueNameValidator


class DevIdAddMethodSelectForm(forms.Form):
    """Form for selecting the method to add an DevID Onboarding Pattern.

    Attributes:
        method_select (ChoiceField): A dropdown to select the method for adding an Issuing CA.
            - `import_truststore`: Import a new truststore prior to configuring a new pattern.
            - `configure_pattern`: Use an existing truststore to define a new pattern.
    """

    method_select = forms.ChoiceField(
        label=_('Select Method'),
        choices=[
            ('import_truststore', _('Import a new truststore prior to configuring a new pattern')),
            ('configure_pattern', _('Use an existing truststore to define a new pattern')),
        ],
        initial='configure_pattern',
        required=True,
    )


class DevIdRegistrationForm(forms.ModelForm[DevIdRegistration]):
    """Form to create a new DevIdRegistration."""

    class Meta:  # noqa: D106
        model = DevIdRegistration
        fields: ClassVar[list[str]] = ['unique_name', 'truststore', 'domain', 'serial_number_pattern']
        widgets: ClassVar[dict[str, Any]] = {
            'serial_number_pattern': forms.TextInput(
                attrs={
                    'placeholder': 'Enter a regex pattern for serial numbers',
                }
            ),
        }
        labels: ClassVar[dict[str, str]] = {
            'unique_name': 'Unique Name',
            'truststore': 'Associated Truststore',
            'domain': 'Associated Domain',
            'serial_number_pattern': 'Serial Number Pattern (Regex)',
        }


    unique_name = forms.CharField(
        max_length=256,
        label=_('[Optional] Unique Name'),
        widget=forms.TextInput(attrs={'autocomplete': 'nope'}),
        required=False,
        validators=[UniqueNameValidator()],
    )

    def clean(self) -> None:
        """Cleans and validates the form data.

        Ensures the unique name is not already used if provided.

        Raises:
            ValidationError: If the unique name is not unique.
        """
        cleaned_data = super().clean()
        if cleaned_data is None:
            exc_msg = 'No data was provided.'
            raise ValidationError(exc_msg)
        unique_name = cleaned_data.get('unique_name')
        truststore_name = cleaned_data.get('truststore')

        if not unique_name and truststore_name:
            unique_name = truststore_name.unique_name
            cleaned_data['unique_name'] = unique_name

        if unique_name and DevIdRegistration.objects.filter(unique_name=unique_name).exists():
            error_message = 'DevID Registration with the provided name already exists.'
            raise ValidationError(error_message)

        self.cleaned_data = cleaned_data
