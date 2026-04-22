"""Views for the network discovery dashboard and port management."""

import csv
import threading
from typing import Any

from django.contrib import messages
from django.db.models import Q
from django.http import HttpRequest, HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.views.decorators.http import require_POST

from pki.models.certificate import CertificateModel

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
        with cls._lock:
            cls.stop_pending = True
            if cls.scanner_instance:
                cls.scanner_instance.stop_requested.set()

    @classmethod
    def end_scan(cls) -> None:
        with cls._lock:
            cls.is_running = False
            cls.stop_pending = False
            cls.scanner_instance = None

    @classmethod
    def get_state(cls) -> dict[str, Any]:
        with cls._lock:
            return {
                'scan_running': cls.is_running,
                'stop_pending': cls.stop_pending,
                'start_ip': cls.start_ip,
                'end_ip': cls.end_ip,
            }


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


def device_list(request: HttpRequest) -> HttpResponse:
    """Display the asset discovery dashboard with scan results and port config."""
    all_devs = DiscoveredDevice.objects.all().order_by('-last_seen')
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

    # Safely get the current variables
    state = ScanManager.get_state()

    return render(
        request,
        'discovery/device_list.html',
        {
            'devices': all_devs,
            'scan_ports': all_ports,
            'scan_running': state['scan_running'],
            'stop_pending': state['stop_pending'],
            'stats': stats,
            'start_ip': state['start_ip'],
            'end_ip': state['end_ip'],
        },
    )


@require_POST
def start_scan(request: HttpRequest) -> HttpResponse:
    """Initialize and start a background network scan."""
    start_ip = request.POST.get('start_ip', '10.100.13.1')
    end_ip = request.POST.get('end_ip', '10.100.13.254')
    
    if ScanManager.begin_scan(start_ip, end_ip):
        thread = threading.Thread(target=run_scan_in_background, args=(start_ip, end_ip))
        thread.daemon = True
        thread.start()
        messages.success(request, "Network scan started.")
    else:
        messages.warning(request, "A scan is already running.")
        
    return redirect('discovery:device_list')


@require_POST 
def stop_scan(request: HttpRequest) -> HttpResponse:  # noqa: ARG001
    """Request the active scan to terminate."""
    ScanManager.request_stop()
    messages.info(request, "Stopping the scan...")
    return redirect('discovery:device_list')


@require_POST
def add_port(request: HttpRequest) -> HttpResponse:
    """Add a new port to the scan configuration."""
    port_str = request.POST.get('port_number')
    desc = request.POST.get('description')
    
    if port_str and desc:
        try:
            port_int = int(port_str)
            DiscoveryPort.objects.get_or_create(port_number=port_int, description=desc)
            messages.success(request, f'Port {port_int} added to scan configuration.')
        except ValueError:
            messages.error(request, 'Invalid port number. Please enter a valid integer.')
            
    return redirect('discovery:device_list')


@require_POST
def delete_port(request: HttpRequest, port_id: int) -> HttpResponse:
    """Remove a port from the scan configuration."""
    port = get_object_or_404(DiscoveryPort, id=port_id)
    port_num = port.port_number
    port.delete()
    messages.info(request, f'Port {port_num} removed from scan configuration.')
    return redirect('discovery:device_list')


@require_POST
def clear_devices(request: HttpRequest) -> HttpResponse:
    """Wipe the discovered devices inventory."""
    DiscoveredDevice.objects.all().delete()
    messages.success(request, 'Discovery inventory cleared.')
    return redirect('discovery:device_list')


def device_detail(request: HttpRequest, device_id: int) -> HttpResponse:
    """Show detail view for a discovered device."""
    device = get_object_or_404(DiscoveredDevice, id=device_id)
    return render(request, 'discovery/device_detail.html', {'device': device})


def export_csv(request: HttpRequest) -> HttpResponse:  # noqa: ARG001
    """Export the current discovery inventory to a CSV file."""
    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = 'attachment; filename="inventory.csv"'
    writer = csv.writer(response)
    writer.writerow(['IP', 'Hostname', 'Ports'])
    for d in DiscoveredDevice.objects.all():
        writer.writerow([d.ip_address, d.hostname, ', '.join(map(str, d.open_ports))])
    return response