# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Abstract certificate request forms, independent of the requested certificate type and protocol."""

from __future__ import annotations

from typing import Any, ClassVar, cast

from django import forms
from django.utils.translation import gettext_lazy as _

from pki.key_types import KEY_TYPE_CHOICES
from pki.models.truststore import TruststoreModel
from pki.services.key_generation import supported_key_type_choices

__all__ = [
    'CertificateRequestFormMixin',
    'CertificateTruststoreAssociationForm',
    'EstRequestFormMixin',
]


class CertificateRequestFormMixin(forms.Form):
    """Shared certificate request fields: key type and the remote CA connection.

    Concrete subclasses override ``key_type_choices``, ``key_type_initial``,
    ``remote_port_initial`` and ``remote_path_initial`` and call
    :meth:`_apply_request_defaults` from their ``__init__``.
    """

    key_type_choices = KEY_TYPE_CHOICES
    key_type_initial = 'RSA-2048'
    remote_port_initial = 443
    remote_path_initial = ''

    key_type = forms.ChoiceField(
        label=_('Key Type'),
        required=True,
        help_text=_('Select the cryptographic key type and parameters.'),
    )
    remote_host = forms.CharField(
        label=_('Remote Host'),
        max_length=253,
        required=True,
        help_text=_('The hostname or IP address of the remote PKI.'),
    )
    remote_port = forms.IntegerField(
        label=_('Remote Port'),
        min_value=1,
        max_value=65535,
        required=True,
        help_text=_('The port number of the remote PKI.'),
    )
    remote_path = forms.CharField(
        label=_('Remote Path'),
        max_length=255,
        required=True,
        help_text=_('The path on the remote PKI.'),
    )

    def _apply_request_defaults(self) -> None:
        """Apply the cert-type-specific defaults to the shared fields."""
        key_type_field = cast('forms.ChoiceField', self.fields['key_type'])
        key_type_field.choices = supported_key_type_choices(self.key_type_choices)
        key_type_field.initial = self.key_type_initial
        self.fields['remote_port'].initial = self.remote_port_initial
        if self.remote_path_initial:
            self.fields['remote_path'].initial = self.remote_path_initial


class EstRequestFormMixin(CertificateRequestFormMixin):
    """EST request fields: shared request fields plus EST username/password authentication."""

    remote_path_initial = '/.well-known/est/simpleenroll'
    est_authentication_required = False

    est_username = forms.CharField(
        label=_('EST Username'),
        max_length=128,
        required=False,
        help_text=_('Username for EST authentication.'),
    )
    est_password = forms.CharField(
        label=_('EST Password'),
        widget=forms.PasswordInput,
        max_length=128,
        required=False,
        help_text=_('Password for EST authentication.'),
    )

    def _apply_est_request_defaults(self) -> None:
        """Apply the cert-type-specific defaults, including the EST auth fields."""
        self._apply_request_defaults()
        self.fields['est_username'].required = self.est_authentication_required
        self.fields['est_password'].required = self.est_authentication_required


class CertificateTruststoreAssociationForm(forms.Form):
    """Select the trust store used to validate the externally issued certificate."""

    truststore_intended_usage: ClassVar[TruststoreModel.IntendedUsage] = TruststoreModel.IntendedUsage.TLS

    trust_store = forms.ModelChoiceField(
        queryset=TruststoreModel.objects.none(),
        empty_label='----------',
        required=True,
        label=_('Trust Store'),
        help_text=_('Select a "TLS" trust store containing the external PKI CA chain.'),
    )

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """Limit the choice to the configured truststore usage."""
        intended_usage = kwargs.pop('truststore_intended_usage', self.truststore_intended_usage)
        super().__init__(*args, **kwargs)
        trust_store_field = cast('forms.ModelChoiceField[TruststoreModel]', self.fields['trust_store'])
        trust_store_field.queryset = TruststoreModel.objects.filter(intended_usage=intended_usage)
        trust_store_field.help_text = {
            TruststoreModel.IntendedUsage.TLS: _('Select a "TLS" trust store containing the external PKI CA chain.'),
            TruststoreModel.IntendedUsage.ISSUING_CA_CHAIN: _('Only "Issuing CA Chain" truststores can be associated.'),
        }.get(intended_usage, _('Select a trust store to associate.'))
