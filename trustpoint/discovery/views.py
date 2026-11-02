# Copyright (c) 2024 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Views for the network discovery dashboard and port management."""

import csv
from typing import Any

from django.contrib import messages
from django.core.exceptions import PermissionDenied
from django.db.models import Q
from django.http import HttpRequest, HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.views import View

from trustpoint.views.base import ContextDataMixin
from users.permissions import AppPermissions

from .models import DiscoveredDevice, DiscoveryPort
from .services import ScanManager


class DiscoveryContextMixin(ContextDataMixin):
    """Mixin which adds context_data for the Discovery pages."""

    context_page_category = 'tools'
    context_page_name = 'discovery'


class DeviceListView(DiscoveryContextMixin, View):
    """Display the asset discovery dashboard with scan results and port config."""

    http_method_names = ('get',)

    def _apply_filters(self, queryset: Any, request: HttpRequest) -> tuple[Any, bool]:
        """Apply filters to the device queryset and return filtered queryset and active status."""
        filters_active = False
        ip_address = request.GET.get('ip_address', '').strip()
        hostname = request.GET.get('hostname', '').strip()
        ssl_status = request.GET.get('ssl_status', '').strip()
        port = request.GET.get('port', '').strip()

        if ip_address:
            queryset = queryset.filter(ip_address__icontains=ip_address)
            filters_active = True

        if hostname:
            queryset = queryset.filter(hostname__icontains=hostname)
            filters_active = True

        if ssl_status:
            if ssl_status == 'self_signed':
                queryset = queryset.filter(certificate_record__isnull=False, ssl_info__is_self_signed=True)
            elif ssl_status == 'pki_linked':
                queryset = queryset.filter(certificate_record__isnull=False, ssl_info__is_self_signed=False)
            elif ssl_status == 'none':
                queryset = queryset.filter(certificate_record__isnull=True)
            filters_active = True

        if port:
            try:
                port_num = int(port)
                queryset = queryset.filter(open_ports__contains=[port_num])
                filters_active = True
            except (ValueError, TypeError):
                pass

        return queryset, filters_active

    def get(self, request: HttpRequest) -> HttpResponse:
        """Render the discovery dashboard."""
        all_devs = DiscoveredDevice.objects.all().order_by('-last_seen')

        # Apply filters
        all_devs, filters_active = self._apply_filters(all_devs, request)

        all_ports = DiscoveryPort.objects.all().order_by('port_number')

        stats = {'total': all_devs.count(), 'risks': 0, 'industrial': 0}

        ot_ports = list(
            DiscoveryPort.objects.filter(
                Q(description__icontains='OPC') | Q(description__icontains='MQTT')
            ).values_list('port_number', flat=True)
        )

        for d in all_devs:
            if d.ssl_info and d.ssl_info.get('is_self_signed'):
                stats['risks'] += 1
            if any(p in ot_ports for p in d.open_ports):
                stats['industrial'] += 1

        state = ScanManager.get_state()
        context = self.get_context_data(
            devices=all_devs,
            scan_ports=all_ports,
            scan_running=state['scan_running'],
            stop_pending=state['stop_pending'],
            stats=stats,
            start_ip=state['start_ip'],
            end_ip=state['end_ip'],
            filters_active=filters_active,
        )

        return render(
            request,
            'discovery/device_list.html',
            context,
        )


class StartScanView(View):
    """Initialize and start a background network scan."""

    http_method_names = ('post',)

    def post(self, request: HttpRequest) -> HttpResponse:
        """Queue a background scan when no scan is running."""
        if not request.user.has_perm(AppPermissions.MANAGE_CERTIFICATE_DISCOVERY):
            raise PermissionDenied
        start_ip = request.POST.get('start_ip', '10.100.13.1')
        end_ip = request.POST.get('end_ip', '10.100.13.254')

        try:
            started = ScanManager.begin_scan(start_ip, end_ip)
        except ValueError as exc:
            messages.error(request, str(exc))
            return redirect('discovery:device_list')

        if started:
            messages.success(request, 'Network scan started.')
        else:
            messages.warning(request, 'A scan is already running.')

        return redirect('discovery:device_list')


class StopScanView(View):
    """Request the active scan to terminate."""

    http_method_names = ('post',)

    def post(self, request: HttpRequest) -> HttpResponse:
        """Signal the active scanner to stop."""
        if not request.user.has_perm(AppPermissions.MANAGE_CERTIFICATE_DISCOVERY):
            raise PermissionDenied
        ScanManager.request_stop()
        messages.info(request, 'Stopping the scan...')
        return redirect('discovery:device_list')


class AddPortView(View):
    """Add a new port to the scan configuration."""

    http_method_names = ('post',)

    def post(self, request: HttpRequest) -> HttpResponse:
        """Validate and persist an additional scan port."""
        if not request.user.has_perm(AppPermissions.MANAGE_CERTIFICATE_DISCOVERY):
            raise PermissionDenied
        port_str = request.POST.get('port_number')
        desc = request.POST.get('description')

        if port_str and desc:
            try:
                port_int = int(port_str)
                DiscoveryPort.objects.get_or_create(port_number=port_int, description=desc)
                messages.success(request, f'Port {port_int} added to scan configuration.')
            except ValueError:
                messages.error(request, 'Invalid port number. Please enter a valid integer.')

        referer = request.META.get('HTTP_REFERER', '')
        if 'port-config' in referer:
            return redirect('discovery:port_config')
        return redirect('discovery:device_list')


class PortConfigView(DiscoveryContextMixin, View):
    """Display and manage port configuration."""

    http_method_names = ('get',)

    def get(self, request: HttpRequest) -> HttpResponse:
        """Render the port configuration page."""
        all_ports = DiscoveryPort.objects.all().order_by('port_number')
        context = self.get_context_data(scan_ports=all_ports)
        return render(request, 'discovery/port_config.html', context)


class DeletePortView(View):
    """Remove a port from the scan configuration."""

    http_method_names = ('post',)

    def post(self, request: HttpRequest, port_id: int) -> HttpResponse:
        """Delete a configured scan port by primary key."""
        if not request.user.has_perm(AppPermissions.MANAGE_CERTIFICATE_DISCOVERY):
            raise PermissionDenied
        port = get_object_or_404(DiscoveryPort, id=port_id)
        port_num = port.port_number
        port.delete()
        messages.info(request, f'Port {port_num} removed from scan configuration.')

        referer = request.META.get('HTTP_REFERER', '')
        if 'port-config' in referer:
            return redirect('discovery:port_config')
        return redirect('discovery:device_list')


class ClearDevicesView(View):
    """Wipe the discovered devices inventory."""

    http_method_names = ('post',)

    def post(self, request: HttpRequest) -> HttpResponse:
        """Delete all discovered devices from inventory."""
        if not request.user.has_perm(AppPermissions.MANAGE_CERTIFICATE_DISCOVERY):
            raise PermissionDenied
        DiscoveredDevice.objects.all().delete()
        messages.success(request, 'Discovery inventory cleared.')
        return redirect('discovery:device_list')


class DeviceDetailView(DiscoveryContextMixin, View):
    """Show detail view for a discovered device."""

    http_method_names = ('get',)

    def get(self, request: HttpRequest, device_id: int) -> HttpResponse:
        """Render details for a single discovered device."""
        device = get_object_or_404(DiscoveredDevice, id=device_id)
        context = self.get_context_data(device=device)
        return render(request, 'discovery/device_detail.html', context)


class ExportCsvView(DiscoveryContextMixin, View):
    """Export the current discovery inventory to a CSV file."""

    http_method_names = ('get',)

    def get(self, request: HttpRequest) -> HttpResponse:  # noqa: ARG002
        """Return inventory rows as a downloadable CSV."""
        response = HttpResponse(content_type='text/csv')
        response['Content-Disposition'] = 'attachment; filename="inventory.csv"'
        writer = csv.writer(response)
        writer.writerow(['IP', 'Hostname', 'Ports'])
        for d in DiscoveredDevice.objects.all():
            writer.writerow([d.ip_address, d.hostname, ', '.join(map(str, d.open_ports))])
        return response
