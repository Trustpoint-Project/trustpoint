import threading
import csv
from django.db.models import Q
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from django.http import HttpResponse
from .models import DiscoveredDevice
from .scanner import OTScanner

SCAN_RUNNING = False

def run_scan_in_background(cidr):
    global SCAN_RUNNING
    SCAN_RUNNING = True
    try:
        scanner = OTScanner()
        results = scanner.scan_network(cidr)
        for d in results:
            DiscoveredDevice.objects.update_or_create(
                ip_address=d['ip'],
                defaults={'hostname': d['hostname'], 'open_ports': d['ports'], 'ssl_info': d['ssl_info']}
            )
    except Exception as e:
        print(f"Error: {e}")
    finally:
        SCAN_RUNNING = False

def device_list(request):
    query = request.GET.get('q')
    devices = DiscoveredDevice.objects.all().order_by('-last_seen')
    if query:
        devices = devices.filter(Q(ip_address__icontains=query) | Q(hostname__icontains=query))
    
    all_devs = DiscoveredDevice.objects.all()
    stats = {'total': all_devs.count(), 'risks': 0, 'industrial': 0}
    ot_ports = [502, 102, 44818, 4840, 1883, 8883]
    for d in all_devs:
        if d.ssl_info and d.ssl_info.get('is_self_signed'): stats['risks'] += 1
        if any(p in ot_ports for p in d.open_ports): stats['industrial'] += 1

    return render(request, 'discovery/device_list.html', {
        'devices': devices, 'scan_running': SCAN_RUNNING, 'stats': stats, 'search_query': query
    })

def device_detail(request, device_id):
    device = get_object_or_404(DiscoveredDevice, id=device_id)
    return render(request, 'discovery/device_detail.html', {'device': device})

def start_scan(request):
    global SCAN_RUNNING
    if request.method == 'POST':
        cidr = request.POST.get('cidr', '172.18.0.0/24')
        if not SCAN_RUNNING:
            thread = threading.Thread(target=run_scan_in_background, args=(cidr,))
            thread.daemon = True
            thread.start()
            messages.success(request, f"Scan started on {cidr}. Please wait...")
    return redirect('discovery:device_list')

def export_csv(request):
    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = 'attachment; filename="inventory.csv"'
    writer = csv.writer(response)
    writer.writerow(['IP', 'Hostname', 'Ports', 'SSL'])
    for d in DiscoveredDevice.objects.all():
        writer.writerow([d.ip_address, d.hostname, d.open_ports, d.ssl_info])
    return response
