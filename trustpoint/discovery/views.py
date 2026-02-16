"""Views for the network discovery dashboard and port management."""

import csv
import threading

from django.contrib import messages
from django.db.models import Q
from django.http import HttpRequest, HttpResponse
from django.shortcuts import get_object_or_404, redirect, render

from pki.models.certificate import CertificateModel

from .models import DiscoveredDevice, DiscoveryPort
from .scanner import OTScanner

SCAN_RUNNING = False
STOP_PENDING = False
START_IP = '10.100.13.1'
END_IP = '10.100.13.254'
scanner_instance = OTScanner(target_ports=[])


def run_scan_in_background(start_ip: str, end_ip: str) -> None:
    """Threaded task to perform network scanning and database updates."""
    global SCAN_RUNNING, STOP_PENDING  # noqa: PLW0603
    try:
        ports = list(DiscoveryPort.objects.values_list('port_number', flat=True))
        scanner_instance.target_ports = ports

        results = scanner_instance.scan_network(start_ip, end_ip)

        if scanner_instance.stop_requested.is_set():
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
        SCAN_RUNNING = False
        STOP_PENDING = False


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

    return render(
        request,
        'discovery/device_list.html',
        {
            'devices': all_devs,
            'scan_ports': all_ports,
            'scan_running': SCAN_RUNNING,
            'stop_pending': STOP_PENDING,
            'stats': stats,
            'start_ip': START_IP,
            'end_ip': END_IP,
        },
    )


def start_scan(request: HttpRequest) -> HttpResponse:
    """Initialize and start a background network scan."""
    global SCAN_RUNNING, START_IP, END_IP, STOP_PENDING  # noqa: PLW0603
    if request.method == 'POST':
        START_IP = request.POST.get('start_ip', START_IP)
        END_IP = request.POST.get('end_ip', END_IP)
        if not SCAN_RUNNING:
            scanner_instance.stop_requested.clear()
            SCAN_RUNNING = True
            STOP_PENDING = False
            thread = threading.Thread(target=run_scan_in_background, args=(START_IP, END_IP))
            thread.daemon = True
            thread.start()
    return redirect('discovery:device_list')


def stop_scan(request: HttpRequest) -> HttpResponse:  # noqa: ARG001
    """Request the active scan to terminate."""
    global STOP_PENDING  # noqa: PLW0603
    scanner_instance.stop_requested.set()
    STOP_PENDING = True
    return redirect('discovery:device_list')


def add_port(request: HttpRequest) -> HttpResponse:
    """Add a new port to the scan configuration."""
    if request.method == 'POST':
        port = request.POST.get('port_number')
        desc = request.POST.get('description')
        if port and desc:
            DiscoveryPort.objects.get_or_create(port_number=port, description=desc)
            messages.success(request, f'Port {port} added to scan configuration.')
    return redirect('discovery:device_list')


def delete_port(request: HttpRequest, port_id: int) -> HttpResponse:
    """Remove a port from the scan configuration."""
    port = get_object_or_404(DiscoveryPort, id=port_id)
    port_num = port.port_number
    port.delete()
    messages.info(request, f'Port {port_num} removed from scan configuration.')
    return redirect('discovery:device_list')


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
