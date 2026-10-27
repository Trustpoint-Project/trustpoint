# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Simplified domain-centric view."""

from __future__ import annotations

from datetime import timedelta
from typing import TYPE_CHECKING, Any

from django.contrib import messages
from django.db.models import Prefetch, Q
from django.shortcuts import get_object_or_404, redirect
from django.urls import reverse
from django.utils import timezone
from django.utils.html import format_html
from django.utils.translation import gettext_lazy
from django.views import View
from django.views.generic import ListView

from devices.filters import DeviceFilter
from devices.models import DeviceModel
from devices.presentation import DeviceHealthPresentationMixin, onboarding_progress
from management.models import NotificationModel
from pki.models import CaModel, CertificateModel, DomainModel, IssuedCredentialModel
from pki.services.certificate_health import certificate_health_counts
from trustpoint.views.base import ContextDataMixin
from users.models import TrustpointUser

if TYPE_CHECKING:
    from django.db.models import QuerySet
    from django.http import HttpRequest, HttpResponse, HttpResponseBase
    from django.utils.safestring import SafeString


class SimplifiedDomainOverviewView(DeviceHealthPresentationMixin, ContextDataMixin, ListView[DomainModel]):
    """Simplified domain-centric overview view."""

    template_name = 'home/simplified_overview.html'
    context_object_name = 'domains'
    context_page_category = 'home'
    context_page_name = 'simplified_overview'

    def get_queryset(self) -> QuerySet[DomainModel]:
        """Return the selected domain or the first domain."""
        queryset = (
            DomainModel.objects
            .select_related('issuing_ca__credential__certificate')
            .order_by('unique_name')
        )

        # Get the selected domain from URL parameter
        selected_domain_id = self.request.GET.get('domain')
        return queryset.filter(pk=selected_domain_id) if selected_domain_id else queryset[:1]

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Add additional context for the simplified overview."""
        context = super().get_context_data(**kwargs)

        context['all_domains'] = DomainModel.objects.all().order_by('unique_name')
        context['selected_domain_id'] = self.request.GET.get('domain')

        context['has_available_cas'] = CaModel.objects.filter(
            is_active=True
        ).exclude(
            ca_type__in=[
                CaModel.CaTypeChoice.AUTOGEN_ROOT,
                CaModel.CaTypeChoice.KEYLESS,
            ]
        ).exists()

        for domain in context['domains']:
            devices = domain.devices.select_related('onboarding_config', 'no_onboarding_config').prefetch_related(
                Prefetch(
                    'issued_credentials',
                    queryset=IssuedCredentialModel.objects.select_related('credential__certificate__revoked_certificate'),
                ),
            )

            device_filter = DeviceFilter(self.request.GET, queryset=devices, reference_time=self.health_as_of)
            filtered_devices = device_filter.qs

            domain.total_devices = devices.count()
            domain.device_filter = device_filter

            filters_active = any([
                self.request.GET.get('common_name'),
                self.request.GET.get('serial_number'),
                self.request.GET.get('domain'),
                self.request.GET.get('enrollment_state'),
                self.request.GET.get('domain_credential_state'),
                self.request.GET.get('application_certificate_state'),
                self.request.GET.get('created_at_from'),
                self.request.GET.get('created_at_to'),
            ])
            domain.filters_active = filters_active

            health = certificate_health_counts(
                CertificateModel.objects.filter(credential__issued_credential__domain=domain),
                as_of=self.health_as_of,
            )
            domain.active_certificates = health['active']
            domain.expiring_certificates = health['expiring']
            domain.expired_certificates = health['expired']

            domain_notifications = NotificationModel.objects.filter(
                Q(domain=domain) |
                Q(issuing_ca=domain.issuing_ca) |
                Q(device__domain=domain) |
                Q(certificate__credential__issued_credential__domain=domain) |
                Q(notification_source=NotificationModel.NotificationSource.SYSTEM)
            ).filter(
                notification_type__in=[
                    NotificationModel.NotificationTypes.INFO,
                    NotificationModel.NotificationTypes.WARNING,
                    NotificationModel.NotificationTypes.CRITICAL,
                ],
                created_at__gte=timezone.now() - timedelta(days=7)
            ).distinct().order_by('-created_at')[:5]
            domain.recent_notifications = domain_notifications

            prepared_devices_list: list[Any] = list(filtered_devices)
            for device in prepared_devices_list:
                self._prepare_device_for_table(device)
            domain.prepared_devices = prepared_devices_list

        return context

    def _prepare_device_for_table(self, device: Any) -> None:
        """Prepare device data for table display by adding display attributes."""
        device.onboarding_progress = self._get_onboarding_progress(device)
        device.domain_credential_status = self._get_domain_credential_status(device)
        device.application_certificate_status = self._get_application_certificate_status(device)
        device.clm_button = self._get_clm_button_html(device)

    def _get_onboarding_progress(self, record: DeviceModel) -> dict[str, Any]:
        """Build enrollment display data with this page's empty-state text."""
        return onboarding_progress(
            record,
            empty_protocols_label=str(gettext_lazy('None')),
            unconfigured_label=str(gettext_lazy('None')),
            unconfigured_tooltip=str(gettext_lazy('No onboarding configuration')),
        )

    def _get_clm_button_html(self, record: DeviceModel) -> SafeString:
        """Gets the HTML for the CLM button in the devices table."""
        if record.device_type == DeviceModel.DeviceType.OPC_UA_GDS_PUSH:
            clm_url = reverse('devices:opc_ua_gds_push_certificate_lifecycle_management', kwargs={'pk': record.pk})
        else:
            clm_url = reverse('devices:devices_certificate_lifecycle_management', kwargs={'pk': record.pk})

        return format_html(
            '<a href="{}" class="btn btn-primary tp-table-btn w-100">{}</a>', clm_url, gettext_lazy('Manage')
        )

    def dispatch(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponseBase:
        """Check if simplified mode is enabled, otherwise redirect to standard dashboard."""
        view_mode = getattr(self.request.user, 'view_mode', TrustpointUser.ViewModeChoices.STANDARD)
        if view_mode != TrustpointUser.ViewModeChoices.SIMPLIFIED:
            return redirect('home:dashboard')

        return super().dispatch(request, *args, **kwargs)


class EnableCrlCycleQuickActionView(View):
    """Quick action to enable CRL cycle with predefined settings (48h cycle, 72h validity)."""

    def post(self, request: HttpRequest, pk: int) -> HttpResponse:
        """Enable CRL cycle updates with preset values."""
        view_mode = getattr(request.user, 'view_mode', TrustpointUser.ViewModeChoices.STANDARD)
        if view_mode != TrustpointUser.ViewModeChoices.SIMPLIFIED:
            return redirect('home:dashboard')

        issuing_ca = get_object_or_404(CaModel, pk=pk)

        if issuing_ca.crl_cycle_enabled:
            messages.info(request, gettext_lazy('CRL cycle updates are already enabled for this CA.'))
        else:
            issuing_ca.crl_cycle_enabled = True
            issuing_ca.crl_cycle_interval_hours = 48.0
            issuing_ca.crl_validity_hours = 72.0
            issuing_ca.save()
            messages.success(
                request,
                gettext_lazy('CRL cycle updates enabled successfully (48h cycle, 72h validity).')
            )

        domain = issuing_ca.domains.first()
        if domain:
            return redirect(f"{reverse('home:simplified_overview')}?domain={domain.pk}")
        return redirect('home:simplified_overview')
