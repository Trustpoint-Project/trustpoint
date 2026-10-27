# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Views for revoking device certificates."""

import datetime
from typing import Any

from django.contrib import messages
from django.core.exceptions import PermissionDenied
from django.db.models import QuerySet
from django.http import Http404, HttpResponse
from django.http.request import HttpRequest
from django.shortcuts import redirect
from django.urls import reverse
from django.utils.translation import gettext_lazy, ngettext
from django.views.generic.detail import DetailView
from django.views.generic.list import ListView

from devices.forms import (
    RevokeDevicesForm,
    RevokeIssuedCredentialForm,
)

# noinspection PyUnresolvedReferences
from devices.models import (
    DeviceModel,
)
from devices.views.mixins import DeviceBulkSelectionMixin
from management.models.audit_log import AuditLog
from onboarding.models import NoOnboardingPkiProtocol
from pki.models import IssuedCredentialModel
from pki.models.certificate import CertificateModel
from pki.services.revocation import revoke_primary_certificate
from trustpoint.page_context import (
    DEVICES_PAGE_CATEGORY,
    DEVICES_PAGE_DEVICES_SUBCATEGORY,
    PageContextMixin,
)
from users.permissions import AppPermissions

DeviceWithoutDomainErrorMsg = gettext_lazy('Device does not have an associated domain.')
NamedCurveMissingForEccErrorMsg = gettext_lazy('Failed to retrieve named curve for ECC algorithm.')
ActiveTrustpointTlsServerCredentialModelMissingErrorMsg = gettext_lazy(
    'No active trustpoint TLS server credential found.'
)

# This only occurs if no domain is configured
PublicKeyInfoMissingErrorMsg = DeviceWithoutDomainErrorMsg

class AbstractIssuedCredentialRevocationView(PageContextMixin, DetailView[IssuedCredentialModel]):
    """Revokes a specific issued credential."""

    http_method_names = ('get', 'post')

    model = IssuedCredentialModel
    template_name = 'devices/confirm_revoke.html'
    context_object_name = 'issued_credential'
    pk_url_kwarg = 'pk'
    form_class = RevokeIssuedCredentialForm

    page_category = DEVICES_PAGE_CATEGORY
    page_name: str

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Adds the primary keys to the context.

        Args:
            kwargs: Keyword arguments are passed to super().get_context_data(**kwargs).

        Returns:
            The context data.
        """
        context = super().get_context_data(**kwargs)
        context['revoke_form'] = self.form_class()
        context['cert'] = self.object.credential.certificate
        context['cred_revoke_url'] = f'{self.page_category}:{self.page_name}_credential_revoke'

        device = self.object.device
        if device and device.no_onboarding_config:
            if device.no_onboarding_config.has_pki_protocol(NoOnboardingPkiProtocol.CMP_SHARED_SECRET):
                context['cmp_revoke_help_url'] = f'{self.page_category}:{self.page_name}_device_revoke_cmp_help'
                context['show_cmp_revoke_help'] = True
            else:
                context['show_cmp_revoke_help'] = False
        else:
            context['show_cmp_revoke_help'] = False

        return context

    def post(self, _request: HttpRequest, *_args: Any, **_kwargs: Any) -> HttpResponse:
        """Will try to revoke the requested issued credential.

        Args:
            request: The Django request object.
            *_args: Positional arguments are discarded.
            **_kwargs: Keyword arguments are discarded.

        Returns:
            Redirect to the devices summary.
        """
        if not self.request.user.has_perm(AppPermissions.REVOKE_CERTIFICATES):
            raise PermissionDenied
        self.object = self.get_object()

        device = self.object.device
        if device is None:
            raise Http404

        reverse_path = reverse(
            f'{self.page_category}:{self.page_name}_certificate_lifecycle_management',
            kwargs={'pk': device.pk},
        )

        revoke_form = self.form_class(self.request.POST)
        if revoke_form.is_valid():
            revocation_reason = revoke_form.cleaned_data['revocation_reason']

            cert = self.object.credential.certificate_or_error
            status = cert.certificate_status
            if status == CertificateModel.CertificateStatus.EXPIRED:
                msg = gettext_lazy('Credential is already expired. Cannot revoke expired certificates.')
                messages.error(self.request, msg)
                return redirect(reverse_path)
            if status == CertificateModel.CertificateStatus.REVOKED:
                msg = gettext_lazy('Certificate is already revoked. Cannot revoke a revoked certificate again.')
                messages.error(self.request, msg)
                return redirect(reverse_path)
            revoked_successfully, _ = revoke_primary_certificate(self.object.id, revocation_reason)
            if revoked_successfully:
                msg = gettext_lazy('Successfully revoked one active credential.')
                messages.success(self.request, msg)
                actor = self.request.user if self.request.user.is_authenticated else None
                domain_name = self.object.domain.unique_name if self.object.domain else 'unknown'
                cred_display = (
                    f'Device: {device.common_name} | Domain: {domain_name}'
                    f' | Credential: {self.object.common_name}'
                )
                AuditLog.create_entry(
                    operation_type=AuditLog.OperationType.CREDENTIAL_REVOKED,
                    target=device,
                    target_display=cred_display,
                    actor=actor,
                )
            else:
                messages.error(
                    self.request, gettext_lazy('Failed to revoke certificate. See logs for more information.')
                )

        return redirect(reverse_path)


class DeviceIssuedCredentialRevocationView(AbstractIssuedCredentialRevocationView):
    """abc."""

    page_name = DEVICES_PAGE_DEVICES_SUBCATEGORY


class OpcUaGdsPushIssuedCredentialRevocationView(AbstractIssuedCredentialRevocationView):
    """abc."""

    page_name = DEVICES_PAGE_DEVICES_SUBCATEGORY

class AbstractBulkRevokeView(DeviceBulkSelectionMixin, PageContextMixin, ListView[DeviceModel]):
    """View to confirm the deletion of multiple Devices."""

    selection_required_message = gettext_lazy('Please select the devices you would like to revoke.')

    model = DeviceModel
    template_name = 'devices/confirm_bulk_revoke.html'
    context_object_name = 'devices'

    missing: str = ''
    pks: str = ''
    queryset: QuerySet[DeviceModel]
    form_class = RevokeDevicesForm

    page_category = DEVICES_PAGE_CATEGORY
    page_name: str

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Adds the primary keys to the context.

        Args:
            kwargs: Keyword arguments are passed to super().get_context_data(**kwargs).

        Returns:
            The context data.
        """
        context = super().get_context_data(**kwargs)
        context['pks'] = self.pks
        context['revoke_form'] = self.form_class(initial={'pks': self.pks})
        context['device_revoke_url'] = f'{self.page_category}:{self.page_name}_device_revoke'
        return context

    def get(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        """HTTP GET processing.

        Args:
            request: The Django request object.
            *args: Positional arguments passed to super().get().
            **kwargs: Keyword arguments passed to super().get().

        Returns:
            The device deletion view or a redirect to the devices view if one or more pks were not found.
        """
        redirect_name = self._set_queryset(request)
        if redirect_name:
            return redirect(redirect_name)
        messages.warning(
            request, gettext_lazy('This operation will revoke ALL certificates associated with the selected devices.')
        )
        return super().get(request, *args, **kwargs)

    def post(self, request: HttpRequest, *_args: Any, **_kwargs: Any) -> HttpResponse:
        """Will try to revoke all certificate assiciated with the requested DeviceModel records.

        Args:
            request: The Django request object.
            *_args: Positional arguments are discarded.
            **_kwargs: Keyword arguments are discarded.

        Returns:
            Redirect to the devices summary.
        """
        if not self.request.user.has_perm(AppPermissions.REVOKE_CERTIFICATES):
            raise PermissionDenied
        revoke_form = self.form_class(self.request.POST)
        if revoke_form.is_valid():
            self.pks = revoke_form.cleaned_data['pks']
            revocation_reason = revoke_form.cleaned_data['revocation_reason']
            redirect_name = self._set_queryset(request)
            if redirect_name:
                return redirect(redirect_name)

            now = datetime.datetime.now(datetime.UTC)

            issued_credentials_to_revoke_qs = IssuedCredentialModel.objects.filter(
                device__in=self.queryset,
                credential__certificate__revoked_certificate__isnull=True,
                credential__certificate__not_valid_after__gte=now,
            ).select_related('device', 'domain')

            n_revoked = 0
            for credential in issued_credentials_to_revoke_qs:
                revoked_successfully, _ = revoke_primary_certificate(
                    credential.id, revocation_reason
                )
                if revoked_successfully:
                    n_revoked += 1
                    actor = request.user if request.user.is_authenticated else None
                    device_name = credential.device.common_name if credential.device else 'unknown'
                    domain_name = credential.domain.unique_name if credential.domain else 'unknown'
                    cred_display = (
                        f'Device: {device_name} | Domain: {domain_name}'
                        f' | Credential: {credential.common_name}'
                    )
                    AuditLog.create_entry(
                        operation_type=AuditLog.OperationType.CREDENTIAL_REVOKED,
                        target=credential.device,
                        target_display=cred_display,
                        actor=actor,
                    )

            if n_revoked > 0:
                msg = ngettext(
                    'Successfully revoked one active credential.',
                    'Successfully revoked %(count)d active credentials.',
                    n_revoked,
                ) % {'count': n_revoked}

                messages.success(self.request, msg)
            else:
                messages.error(self.request, gettext_lazy('No credentials were revoked.'))

        return redirect('devices:devices')


class DeviceBulkRevokeView(AbstractBulkRevokeView):
    """abc."""

    page_name = DEVICES_PAGE_DEVICES_SUBCATEGORY


class OpcUaGdsPushBulkRevokeView(AbstractBulkRevokeView):
    """abc."""

    page_name = DEVICES_PAGE_DEVICES_SUBCATEGORY
