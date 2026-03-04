from __future__ import annotations

from django.contrib.auth.mixins import LoginRequiredMixin
from django.http import HttpRequest, JsonResponse
from django.views import View

from devices.models import DeviceModel
from pki.models.domain import DomainModel
from pki.models.issuing_ca import IssuingCaModel


class ContextSourcesView(LoginRequiredMixin, View):
    def get(self, request: HttpRequest) -> JsonResponse:
        cas = []
        for ca in IssuingCaModel.objects.select_related("credential__certificate").all().order_by("unique_name"):
            cas.append({
                "id": str(ca.id),
                "name": ca.unique_name,
                "common_name": getattr(ca, "common_name", "") or "",
                "type": int(ca.issuing_ca_type) if ca.issuing_ca_type is not None else None,
                "is_active": bool(getattr(ca, "is_active", True)),
            })

        domains = []
        for d in DomainModel.objects.select_related("issuing_ca").all().order_by("unique_name"):
            domains.append({
                "id": str(d.id),
                "name": d.unique_name,
                "is_active": bool(getattr(d, "is_active", True)),
                "issuing_ca_id": str(d.issuing_ca_id) if d.issuing_ca_id else None,
                "issuing_ca_name": d.issuing_ca.unique_name if d.issuing_ca_id else "",
            })

        devices = []
        for dev in DeviceModel.objects.select_related("domain").all().order_by("common_name"):
            devices.append({
                "id": str(dev.id),
                "name": dev.common_name,
                "serial_number": dev.serial_number or "",
                "device_type": int(dev.device_type) if dev.device_type is not None else None,
                "domain_id": str(dev.domain_id) if dev.domain_id else None,
                "domain_name": dev.domain.unique_name if dev.domain_id else "",
            })

        return JsonResponse({"cas": cas, "domains": domains, "devices": devices})
    