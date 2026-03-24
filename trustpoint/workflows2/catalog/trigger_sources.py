from __future__ import annotations

from typing import Any

from devices.models import DeviceModel
from pki.models import CaModel, DomainModel


def build_trigger_source_catalog() -> dict[str, Any]:
    cas = [
        {
            'id': ca.id,
            'title': ca.unique_name,
            'active': bool(ca.is_active),
            'type': ca.get_ca_type_display() if ca.ca_type is not None else '',
        }
        for ca in CaModel.objects.only('id', 'unique_name', 'is_active', 'ca_type').order_by('unique_name')
    ]

    domains = [
        {
            'id': domain.id,
            'title': domain.unique_name,
            'active': bool(domain.is_active),
            'issuing_ca_id': domain.issuing_ca_id,
            'issuing_ca_title': domain.issuing_ca.unique_name if domain.issuing_ca_id else '',
        }
        for domain in (
            DomainModel.objects.select_related('issuing_ca')
            .only('id', 'unique_name', 'is_active', 'issuing_ca_id', 'issuing_ca__unique_name')
            .order_by('unique_name')
        )
    ]

    devices = [
        {
            'id': str(device.id),
            'title': device.common_name,
            'serial_number': device.serial_number or '',
            'domain_id': device.domain_id,
            'domain_title': device.domain.unique_name if device.domain_id else '',
        }
        for device in (
            DeviceModel.objects.select_related('domain')
            .only('id', 'common_name', 'serial_number', 'domain_id', 'domain__unique_name')
            .order_by('common_name')
        )
    ]

    return {
        'cas': cas,
        'domains': domains,
        'devices': devices,
    }
