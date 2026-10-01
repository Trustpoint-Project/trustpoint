# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Forms for certificate signing request based issuance."""

from django import forms
from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _

from pki.services.csr import CsrValidationError, parse_csr


class CsrIssuanceForm(forms.Form):
    """Accept exactly one externally generated CSR."""

    csr_text = forms.CharField(
        label=_('Paste CSR'),
        required=False,
        widget=forms.Textarea(attrs={'rows': 14}),
    )
    csr_file = forms.FileField(label=_('Upload CSR'), required=False)

    def clean(self) -> dict[str, object]:
        """Read and validate the selected CSR source."""
        cleaned_data = super().clean() or {}
        text = str(cleaned_data.get('csr_text') or '').strip()
        uploaded = cleaned_data.get('csr_file')
        if bool(text) == bool(uploaded):
            raise ValidationError(_('Provide exactly one CSR by pasting it or uploading a file.'))

        if text:
            data = text.encode()
        else:
            read_uploaded = getattr(uploaded, 'read', None)
            if not callable(read_uploaded):
                raise ValidationError(_('Provide exactly one CSR by pasting it or uploading a file.'))
            data = read_uploaded()
        try:
            cleaned_data['csr'] = parse_csr(data)
        except CsrValidationError as exc:
            raise ValidationError(str(exc)) from exc
        return cleaned_data
