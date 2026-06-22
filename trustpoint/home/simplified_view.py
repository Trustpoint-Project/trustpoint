"""Simplified domain-centric view."""

from __future__ import annotations

from datetime import timedelta
from typing import TYPE_CHECKING, Any

from django.contrib import messages
from django.db.models import Q
from django.shortcuts import get_object_or_404, redirect
from django.urls import reverse
from django.utils import timezone
from django.utils.html import format_html
from django.utils.translation import gettext_lazy
from django.views import View
from django.views.generic import ListView

from devices.filters import DeviceFilter
from devices.models import DeviceModel
from management.models import NotificationModel, UIConfig
from onboarding.enums import OnboardingStatus
from pki.models import CaModel, CertificateModel, DomainModel, IssuedCredentialModel
from trustpoint.views.base import ContextDataMixin

if TYPE_CHECKING:
    from django.db.models import QuerySet
    from django.http import HttpRequest, HttpResponse, HttpResponseBase
    from django.utils.safestring import SafeString


class SimplifiedDomainOverviewView(ContextDataMixin, ListView[DomainModel]):
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
            .prefetch_related('devices')
            .order_by('unique_name')
        )

        # Get the selected domain from URL parameter
        selected_domain_id = self.request.GET.get('domain')
        return queryset.filter(pk=selected_domain_id) if selected_domain_id else queryset[:1]

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Add additional context for the simplified overview."""
        context = super().get_context_data(**kwargs)

        # Get all domains for the selector
        context['all_domains'] = DomainModel.objects.all().order_by('unique_name')
        context['selected_domain_id'] = self.request.GET.get('domain')

        # Get certificate statistics and prepare devices for each domain
        for domain in context['domains']:
            devices = domain.devices.all()

            device_filter = DeviceFilter(self.request.GET, queryset=devices)
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

            active_certs = CertificateModel.objects.filter(
                credential__issued_credential__domain=domain,
                revoked_certificate__isnull=True,
                not_valid_after__gt=timezone.now(),
            ).count()

            expiring_certs = CertificateModel.objects.filter(
                credential__issued_credential__domain=domain,
                revoked_certificate__isnull=True,
                not_valid_after__lte=timezone.now() + timedelta(days=30),
                not_valid_after__gt=timezone.now(),
            ).count()

            expired_certs = CertificateModel.objects.filter(
                credential__issued_credential__domain=domain,
                revoked_certificate__isnull=True,
                not_valid_after__lte=timezone.now(),
            ).count()

            domain.active_certificates = active_certs
            domain.expiring_certificates = expiring_certs
            domain.expired_certificates = expired_certs

            # Get recent notifications for this domain
            # Filter by domain, issuing_ca, devices in domain, certificates in domain, or system notifications
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

            # Prepare filtered devices with table data
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
        """Builds structured progress data for the enrollment column."""
        if record.onboarding_config:
            cfg = record.onboarding_config
            is_onboarded = cfg.onboarding_status == OnboardingStatus.ONBOARDED
            status_key = 'onboarded' if is_onboarded else 'pending'
            status_label = str(gettext_lazy('Onboarded') if is_onboarded else gettext_lazy('Pending'))
            onboarding_protocol = str(cfg.get_onboarding_protocol_display())
            pki_labels = [str(p.label) for p in cfg.get_pki_protocols()]
            none_str = str(gettext_lazy('None'))
            pki_list = ''.join(f'<li>{p}</li>' for p in pki_labels) if pki_labels else f'<li>{none_str}</li>'
            pki_protocols = ', '.join(pki_labels) if pki_labels else none_str
            tooltip = (
                f'<strong>{gettext_lazy("Onboarding Protocol")}:</strong> {onboarding_protocol}<br>'
                f'<strong>{gettext_lazy("Status")}:</strong> {status_label}<br>'
                f'<strong>{gettext_lazy("PKI Protocols")}:</strong>'
                f'<ul class="mb-0 ps-3 mt-1">{pki_list}</ul>'
            )
        elif record.no_onboarding_config:
            pki_labels = [str(p.label) for p in record.no_onboarding_config.get_pki_protocols()]
            none_str = str(gettext_lazy('None'))
            pki_list = ''.join(f'<li>{p}</li>' for p in pki_labels) if pki_labels else f'<li>{none_str}</li>'
            status_key = 'no-onboarding'
            status_label = str(gettext_lazy('No onboarding'))
            onboarding_protocol = '—'
            pki_protocols = ', '.join(pki_labels) if pki_labels else none_str
            tooltip = (
                f'<strong>{gettext_lazy("Enrollment")}:</strong> {gettext_lazy("No onboarding")}<br>'
                f'<strong>{gettext_lazy("PKI Protocols")}:</strong>'
                f'<ul class="mb-0 ps-3 mt-1">{pki_list}</ul>'
            )
        else:
            status_key = 'none'
            status_label = str(gettext_lazy('None'))
            onboarding_protocol = '—'
            pki_protocols = '—'
            tooltip = str(gettext_lazy('No onboarding configuration'))

        return {
            'status_key': status_key,
            'status_label': status_label,
            'onboarding_protocol': onboarding_protocol,
            'pki_protocols': pki_protocols,
            'tooltip': tooltip,
        }

    def _get_domain_credential_status(self, record: DeviceModel) -> dict[str, Any]:
        """Build the domain-credential state for the device table."""
        now = timezone.now()
        certificates = self._get_certificates_for_type(
            record, IssuedCredentialModel.IssuedCredentialType.DOMAIN_CREDENTIAL
        )

        if not certificates:
            return {
                'status_key': 'none',
                'status_label': str(gettext_lazy('None')),
                'tooltip': str(gettext_lazy('No domain credentials issued.')),
            }

        active_certificates = [
            cert for cert in certificates
            if not hasattr(cert, 'revoked_certificate') and cert.not_valid_after > now
        ]
        if active_certificates:
            next_expiry = min(cert.not_valid_after for cert in active_certificates)
            return {
                'status_key': 'active',
                'status_label': str(gettext_lazy('Active')),
                'tooltip': f'{gettext_lazy("Expires")}: {next_expiry.strftime("%Y-%m-%d %H:%M")}',
            }

        return {
            'status_key': 'revoked',
            'status_label': str(gettext_lazy('Revoked/Expired')),
            'tooltip': str(gettext_lazy('All domain credentials are revoked or expired.')),
        }

    def _get_application_certificate_status(self, record: DeviceModel) -> dict[str, Any]:
        """Build the application-certificate state for the device table."""
        now = timezone.now()
        certificates = self._get_certificates_for_type(
            record, IssuedCredentialModel.IssuedCredentialType.APPLICATION_CREDENTIAL
        )

        if not certificates:
            return {
                'status_key': 'none',
                'status_label': str(gettext_lazy('None')),
                'tooltip': str(gettext_lazy('No application certificates issued.')),
            }

        active_certificates = [
            cert for cert in certificates
            if not hasattr(cert, 'revoked_certificate') and cert.not_valid_after > now
        ]
        if active_certificates:
            next_expiry = min(cert.not_valid_after for cert in active_certificates)
            return {
                'status_key': 'active',
                'status_label': str(gettext_lazy('Active')),
                'tooltip': f'{gettext_lazy("Expires")}: {next_expiry.strftime("%Y-%m-%d %H:%M")}',
            }

        return {
            'status_key': 'revoked',
            'status_label': str(gettext_lazy('Revoked/Expired')),
            'tooltip': str(gettext_lazy('All application certificates are revoked or expired.')),
        }

    def _get_certificates_for_type(
        self, record: DeviceModel, credential_type: IssuedCredentialModel.IssuedCredentialType
    ) -> list[CertificateModel]:
        """Get all certificates for a specific credential type."""
        return list(
            CertificateModel.objects.filter(
                credential__issued_credential__device=record,
                credential__issued_credential__issued_credential_type=credential_type,
            ).select_related('revoked_certificate')
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
        ui_config = UIConfig.get_current()
        if not ui_config.is_simplified_mode:
            return redirect('home:dashboard')

        return super().dispatch(request, *args, **kwargs)


class EnableCrlCycleQuickActionView(View):
    """Quick action to enable CRL cycle with predefined settings (48h cycle, 72h validity)."""

    def post(self, request: HttpRequest, pk: int) -> HttpResponse:
        """Enable CRL cycle updates with preset values."""
        ui_config = UIConfig.get_current()
        if not ui_config.is_simplified_mode:
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
