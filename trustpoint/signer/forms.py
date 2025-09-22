"""Contains Logic for Form on Add/Edit Signer Page."""

from typing import Any, ClassVar, cast

from crispy_forms.helper import FormHelper
from django import forms
from django.core.exceptions import ValidationError
from django.forms import ModelForm
from trustpoint_core.oid import AlgorithmIdentifier, NamedCurve

from trustpoint.signer.models import Signer


class SignerForm(ModelForm[Signer]):
    """Creates Form to create/modify Signers."""

    class Meta:
        """Metaclass."""

        model = Signer
        fields: ClassVar = ['unique_name', 'signing_algorithm', 'key_length', 'curve', 'hash_function', 'expires_by']
        widgets: ClassVar = {
            'expires_by': forms.DateTimeInput(attrs={'type': 'datetime-local'}),
        }

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """Initializes the SignerForm."""
        super().__init__(*args, **kwargs)
        self.helper = FormHelper()
        self.helper.form_tag = False

        if self.instance and self.instance.pk:
            for field_name in self.fields:
                if field_name != 'unique_name':
                    self.fields[field_name].disabled = True

    def clean_unique_name(self) -> str:
        """Ensures check for uniqueness of the name while creating a signer.

        Also let you bypass the check if the signer already exists.(Using the same form for add/modify signers).

        Returns: If check for uniqueness is successful. Returns the uniquename.

        """
        unique_name = cast('str', self.cleaned_data.get('unique_name'))
        if not unique_name:
            err_msg = 'Unique name is required.'
            raise ValidationError(err_msg)

        qs = Signer.objects.filter(unique_name=unique_name)
        if self.instance.pk:
            qs = qs.exclude(pk=self.instance.pk)

        if qs.exists():
            err_msg = 'Signer already exists.'
            raise ValidationError(err_msg)

        return unique_name

    def clean(self) -> dict[str, Any]:  # noqa: C901
        """This functions validates, checks and parse the data from the form.

        Returns: Cleaned and validated data from the form.

        """
        cleaned_data: dict[str, Any] = super().clean() or {}

        algorithm_oid_str = cleaned_data.get('signing_algorithm')
        key_length = cleaned_data.get('key_length')
        expires_by = cleaned_data.get('expires_by')
        curve_input = cleaned_data.get('curve')

        if not algorithm_oid_str:
            msg = 'Signing algorithm is required.'
            raise ValidationError(msg)

        algorithm_enum = None
        for enum_member in AlgorithmIdentifier:
            if getattr(enum_member, 'dotted_string', None) == algorithm_oid_str:
                algorithm_enum = enum_member
                break

        if algorithm_enum is None:
            msg = f'Invalid algorithm: {algorithm_oid_str}'
            raise ValidationError(msg)

        if algorithm_enum.public_key_algo_oid is None:
            msg = 'Public key oid cannot be None.'
            raise ValidationError(msg)
        if algorithm_enum.public_key_algo_oid.name == 'ECC':
            if not curve_input:
                self.add_error('curve', 'Curve must be selected for ECC-based algorithms.')
            available_curves = [c.ossl_curve_name for c in NamedCurve]
            if curve_input not in available_curves:
                self.add_error('curve', f'Invalid ECC curve: {curve_input}')

            cleaned_data['key_length'] = None

        else:
            if not key_length:
                msg = 'Key length must be selected for RSA-based algorithms.'
                raise ValidationError(msg)
            if int(key_length) not in [2048, 3072, 4096, 8192]:
                msg = 'Unsupported key length. Choose 2048, 3072, 4096, or 8192.'
                raise ValidationError(msg)
            cleaned_data['curve'] = None

        if not expires_by:
            msg = 'Expiration date is required.'
            raise ValidationError(msg)

        return cleaned_data