# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Abstract CMP request form, independent of the requested certificate type."""

from __future__ import annotations

from django import forms
from django.utils.translation import gettext_lazy as _

from pki.forms.est_request import CertificateRequestFormMixin

__all__ = ['CmpRequestFormMixin']


class CmpRequestFormMixin(CertificateRequestFormMixin):
    """CMP request fields: shared request fields plus CMP shared-secret authentication."""

    remote_path_initial = '/.well-known/cmp/p/certification'

    cmp_shared_secret = forms.CharField(
        label=_('CMP Shared Secret'),
        widget=forms.PasswordInput,
        max_length=128,
        required=True,
        help_text=_('Shared secret for CMP authentication.'),
    )
    cmp_sender_kid = forms.IntegerField(
        label=_('CMP Sender KID'),
        min_value=0,
        required=False,
        help_text=_('Optional sender key identifier for CMP shared-secret authentication.'),
    )

    def _apply_cmp_request_defaults(self) -> None:
        """Apply the cert-type-specific defaults, including the CMP auth fields."""
        self._apply_request_defaults()
