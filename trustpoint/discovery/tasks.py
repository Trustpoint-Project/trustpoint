# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Background network discovery and inventory updates."""

from django.db import transaction
from django.utils import timezone

from discovery.models import DiscoveredDevice, DiscoveryPort, DiscoveryScan
from discovery.scanner import OTScanner
from pki.models.certificate import CertificateModel

_WRITE_BATCH_SIZE = 200


def _flush_batch(batch: list[DiscoveredDevice]) -> None:
    """Write one batch of hosts with a single upsert statement."""
    with transaction.atomic():
        DiscoveredDevice.objects.bulk_create(
            batch,
            update_conflicts=True,
            unique_fields=['ip_address'],
            update_fields=['hostname', 'open_ports', 'ssl_info', 'certificate_record', 'last_seen'],
        )


def run_scan(scan_id: str) -> None:
    """Claim one queued scan, honor shared cancellation, and release its state."""
    active = DiscoveryScan.objects.filter(pk=1, scan_id=scan_id, is_running=True)
    if not active.filter(started_at__isnull=True, stop_pending=False).update(started_at=timezone.now()):
        return

    def should_stop() -> bool:
        return not active.filter(stop_pending=False).exists()

    try:
        state = active.get()
        if should_stop():
            return
        ports = list(DiscoveryPort.objects.values_list('port_number', flat=True))
        scanner = OTScanner(target_ports=ports)
        results = scanner.scan_network(state.start_ip, state.end_ip, should_stop=should_stop)
        batch: list[DiscoveredDevice] = []
        for result in results:
            if should_stop():
                break
            pki_cert = None
            ssl_info = result.get('ssl_info')
            if ssl_info and 'cert_object' in ssl_info:
                try:
                    cert_obj = ssl_info.pop('cert_object')
                    with transaction.atomic():
                        pki_cert = CertificateModel.save_certificate(cert_obj)
                except Exception:  # noqa: BLE001, S110
                    pass
            batch.append(
                DiscoveredDevice(
                    ip_address=result['ip'],
                    hostname=result.get('hostname') or '',
                    open_ports=result['ports'],
                    ssl_info=ssl_info,
                    certificate_record=pki_cert,
                )
            )
            if len(batch) >= _WRITE_BATCH_SIZE:
                _flush_batch(batch)
                batch.clear()
        if batch:
            _flush_batch(batch)
    finally:
        active.update(is_running=False, stop_pending=False, claimed_at=None, started_at=None)
