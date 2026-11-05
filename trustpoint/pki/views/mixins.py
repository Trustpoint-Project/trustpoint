# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Shared behavior for certificate profile selection in PKI forms."""

from __future__ import annotations

from typing import TYPE_CHECKING, ClassVar

from pki.models.cert_profile import CertificateProfileModel

if TYPE_CHECKING:
    from django.http import HttpRequest


class CertificateProfileSelectionMixin:
    """Select a requested profile, then the configured default, then the first profile."""

    default_profile_name: ClassVar[str]
    available_profiles: list[CertificateProfileModel]

    def _resolve_cert_profile(self, request: HttpRequest) -> CertificateProfileModel | None:
        """Resolve a profile while making the ordered choices available to the view."""
        profiles = list(CertificateProfileModel.objects.order_by('display_name', 'unique_name'))
        if not profiles:
            return None
        self.available_profiles = profiles

        selected_pk = request.GET.get('cert_profile_pk') or request.POST.get('cert_profile_pk')
        if selected_pk:
            try:
                requested_pk = int(selected_pk)
            except (ValueError, TypeError):
                pass
            else:
                for profile in profiles:
                    if profile.pk == requested_pk:
                        return profile

        return next((profile for profile in profiles if profile.unique_name == self.default_profile_name), profiles[0])
