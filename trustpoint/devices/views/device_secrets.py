# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Dedicated page for replacing device enrollment secrets."""

from typing import Any

from django.contrib import messages
from django.core.exceptions import ValidationError
from django.http import HttpResponse
from django.shortcuts import get_object_or_404
from django.urls import reverse
from django.utils.translation import gettext_lazy as _
from django.views.generic.edit import FormView

from devices.forms import ChangeDeviceSecretForm
from devices.models import DeviceModel
from trustpoint.page_context import DEVICES_PAGE_CATEGORY, DEVICES_PAGE_DEVICES_SUBCATEGORY, PageContextMixin
from trustpoint.views.base import UserPermissionRequiredMixin
from users.permissions import AppPermissions


class DeviceSecretChangeView(UserPermissionRequiredMixin, PageContextMixin, FormView[ChangeDeviceSecretForm]):
    """Replace an eligible secret with device management permission."""

    form_class = ChangeDeviceSecretForm
    template_name = 'devices/credentials/change_secret.html'
    permission_required = AppPermissions.MANAGE_DEVICES
    page_category = DEVICES_PAGE_CATEGORY
    page_name = DEVICES_PAGE_DEVICES_SUBCATEGORY

    def get_form_kwargs(self) -> dict[str, Any]:
        """Load the device for the replacement form."""
        kwargs = super().get_form_kwargs()
        kwargs['device'] = get_object_or_404(DeviceModel, pk=self.kwargs['pk'])
        return kwargs

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Include the device and return link."""
        context = super().get_context_data(**kwargs)
        context['device'] = context['form'].device
        context['clm_url'] = self.get_success_url()
        return context

    def get_success_url(self) -> str:
        """Return to the device's certificate lifecycle management page."""
        return reverse('devices:devices_certificate_lifecycle_management', kwargs={'pk': self.kwargs['pk']})

    def form_valid(self, form: ChangeDeviceSecretForm) -> HttpResponse:
        """Replace the secret, keeping lifecycle errors on this page."""
        try:
            form.save(actor=self.request.user)
        except ValidationError as exc:
            form.add_error(None, exc)
            return self.form_invalid(form)
        messages.success(self.request, _('The device secret was replaced. The previous value no longer works.'))
        return super().form_valid(form)
