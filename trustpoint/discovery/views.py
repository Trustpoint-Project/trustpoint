import threading
import csv
from django.db.models import Q
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from django.http import HttpResponse
from .models import DiscoveredDevice
from .scanner import OTScanner
from pki.models.certificate import CertificateModel 

# GLOBALS: Track scan state and the persistent IP address
SCAN_RUNNING = False
CURRENT_CIDR = "192.168.1.0/24" 
scanner_instance = OTScanner()

def run_scan_in_background(cidr):
    global SCAN_RUNNING
    try:
        results = scanner_instance.scan_network(cidr)
        for d in results:
            pki_cert = None
            ssl_info = d.get('ssl_info')
            
            if ssl_info and 'cert_object' in ssl_info:
                try:
                    cert_obj = ssl_info.pop('cert_object')
                    pki_cert = CertificateModel.save_certificate(cert_obj)
                except Exception as e:
                    print(f"PKI Error: {e}")

            DiscoveredDevice.objects.update_or_create(
                ip_address=d['ip'],
                defaults={
                    'hostname': d['hostname'], 
                    'open_ports': d['ports'], 
                    'ssl_info': ssl_info,
                    'certificate_record': pki_cert
                }
            )
    except Exception as e:
        print(f"Scan Error: {e}")
    finally:
        SCAN_RUNNING = False

def device_list(request):
    """Main dashboard view for discovered devices."""
    query = request.GET.get('q')
    devices = DiscoveredDevice.objects.all().order_by('-last_seen')
    
    if query:
        devices = devices.filter(Q(ip_address__icontains=query) | Q(hostname__icontains=query))
    
    # Calculate stats for the dashboard cards
    all_devs = DiscoveredDevice.objects.all()
    stats = {'total': all_devs.count(), 'risks': 0, 'industrial': 0}
    ot_ports = [502, 102, 44818, 4840, 1883, 8883]
    
    for d in all_devs:
        # Check for risks (self-signed)
        if d.ssl_info and d.ssl_info.get('is_self_signed'): 
            stats['risks'] += 1
        # Check for industrial/OT protocols
        if any(p in ot_ports for p in d.open_ports): 
            stats['industrial'] += 1

    return render(request, 'discovery/device_list.html', {
        'devices': devices, 
        'scan_running': SCAN_RUNNING, 
        'stats': stats, 
        'cidr': CURRENT_CIDR,  
        'search_query': query
    })

def device_detail(request, device_id):
    """Detail view for a single discovered device."""
    device = get_object_or_404(DiscoveredDevice, id=device_id)
    return render(request, 'discovery/device_detail.html', {'device': device})

def start_scan(request):
    """Trigger the background scan."""
    global SCAN_RUNNING, CURRENT_CIDR
    if request.method == 'POST':
        CURRENT_CIDR = request.POST.get('cidr', CURRENT_CIDR)
        if not SCAN_RUNNING:
            scanner_instance.stop_requested.clear()
            SCAN_RUNNING = True 
            thread = threading.Thread(target=run_scan_in_background, args=(CURRENT_CIDR,))
            thread.daemon = True
            thread.start()
            messages.success(request, f"Scan started on {CURRENT_CIDR}.")
    return redirect('discovery:device_list')

def stop_scan(request):
    """Signals the scanner to terminate."""
    global SCAN_RUNNING
    scanner_instance.stop_requested.set()
    messages.info(request, "Scan stop requested. Cleaning up threads...")
    return redirect('discovery:device_list')

def export_csv(request):
    """Generates and downloads a CSV of the discovery inventory."""
    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = 'attachment; filename="inventory.csv"'
    
    writer = csv.writer(response)
    writer.writerow(['IP Address', 'Hostname', 'Open Ports', 'SSL Info'])
    
    for d in DiscoveredDevice.objects.all():
        writer.writerow([
            d.ip_address, 
            d.hostname or 'N/A', 
            ", ".join(map(str, d.open_ports)), 
            d.ssl_info
        ])
    return response