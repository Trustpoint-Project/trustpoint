"""Views for the network discovery dashboard and port management."""

import csv
import threading
from typing import Any

from django.contrib import messages
from django.db.models import Q
from django.http import HttpRequest, HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.views import View

from pki.models.certificate import CertificateModel
from trustpoint.views.base import ContextDataMixin

from .models import DiscoveredDevice, DiscoveryPort
from .scanner import OTScanner


class ScanManager:
    """Thread-safe state manager for the network scanner."""
    _lock = threading.Lock()

    is_running = False
    stop_pending = False
    start_ip = '10.100.13.1'
    end_ip = '10.100.13.254'
    scanner_instance = None

    @classmethod
    def begin_scan(cls, start_ip: str, end_ip: str) -> bool:
        """Starts a new OT device scan, unless one is already running."""
        with cls._lock:
            if cls.is_running:
                return False
            cls.is_running = True
            cls.stop_pending = False
            cls.start_ip = start_ip
            cls.end_ip = end_ip
            cls.scanner_instance = OTScanner(target_ports=[])
            return True

    @classmethod
    def request_stop(cls) -> None:
        """Requests the currently running scan to stop."""
        with cls._lock:
            cls.stop_pending = True
            if cls.scanner_instance:
                cls.scanner_instance.stop_requested.set()

    @classmethod
    def end_scan(cls) -> None:
        """Ends the current scan and resets the state."""
        with cls._lock:
            cls.is_running = False
            cls.stop_pending = False
            cls.scanner_instance = None

    @classmethod
    def get_state(cls) -> dict[str, Any]:
        """Returns the current state of the scan manager."""
        with cls._lock:
            return {
                'scan_running': cls.is_running,
                'stop_pending': cls.stop_pending,
                'start_ip': cls.start_ip,
                'end_ip': cls.end_ip,
            }

    @staticmethod
    def run_scan_in_background(start_ip: str, end_ip: str) -> None:
        """Threaded task to perform network scanning and database updates."""
        try:
            ports = list(DiscoveryPort.objects.values_list('port_number', flat=True))

            # Safely get the active scanner instance
            with ScanManager._lock:
                scanner = ScanManager.scanner_instance

            if scanner:
                scanner.target_ports = ports
                results = scanner.scan_network(start_ip, end_ip)

                if scanner.stop_requested.is_set():
                    return

                for d in results:
                    pki_cert = None
                    ssl_info = d.get('ssl_info')
                    if ssl_info and 'cert_object' in ssl_info:
                        try:
                            cert_obj = ssl_info.pop('cert_object')
                            pki_cert = CertificateModel.save_certificate(cert_obj)
                        except Exception:  # noqa: BLE001, S110
                            pass

                    DiscoveredDevice.objects.update_or_create(
                        ip_address=d['ip'],
                        defaults={
                            'hostname': d.get('hostname') or '',
                            'open_ports': d['ports'],
                            'ssl_info': ssl_info,
                            'certificate_record': pki_cert,
                        },
                    )
        finally:
            # Guarantee the state is reset even if the scanner crashes
            ScanManager.end_scan()


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
        """Start scanning in a background thread when no scan is running."""
        start_ip = request.POST.get('start_ip', '10.100.13.1')
        end_ip = request.POST.get('end_ip', '10.100.13.254')

        if ScanManager.begin_scan(start_ip, end_ip):
            thread = threading.Thread(target=ScanManager.run_scan_in_background, args=(start_ip, end_ip))
            thread.daemon = True
            thread.start()
            messages.success(request, 'Network scan started.')
        else:
            messages.warning(request, 'A scan is already running.')

        return redirect('discovery:device_list')


class StopScanView(View):
    """Request the active scan to terminate."""

    http_method_names = ('post',)

    def post(self, request: HttpRequest) -> HttpResponse:
        """Signal the active scanner to stop."""
        ScanManager.request_stop()
        messages.info(request, 'Stopping the scan...')
        return redirect('discovery:device_list')


class AddPortView(View):
    """Add a new port to the scan configuration."""

    http_method_names = ('post',)

    def post(self, request: HttpRequest) -> HttpResponse:
        """Validate and persist an additional scan port."""
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
