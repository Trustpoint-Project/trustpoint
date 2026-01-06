# workflows/context/strategy/certificate_request.py

from .common import common_workflow_group, common_instance_group
from workflows.context.base import BaseContextStrategy
from workflows.context.registry import register


@register
class CertificateRequestContextStrategy(BaseContextStrategy):
    handler = "certificate_request"

    def get_groups(self, instance):
        er = instance.enrollment_request
        csr_info = instance.payload or {}

        groups = [
            common_workflow_group(instance),
            common_instance_group(instance),
        ]

        # Device group ------------------------------
        if er.device:
            groups.append(
                {
                    "name": "Device",
                    "vars": [
                        {"path": "ctx.device.common_name", "label": "Device common name", "sample": er.device.common_name},
                        {"path": "ctx.device.serial_number", "label": "Device serial number", "sample": er.device.serial_number},
                        {"path": "ctx.device.domain", "label": "Device domain", "sample": er.device.domain.unique_name},
                        {"path": "ctx.device.device_type", "label": "Device type", "sample": er.device.device_type},
                    ],
                }
            )

        # Request group ------------------------------
        groups.append(
            {
                "name": "Request",
                "vars": [
                    {"path": "ctx.request.protocol", "label": "Protocol", "sample": er.protocol},
                    {"path": "ctx.request.operation", "label": "Operation", "sample": er.operation},
                    {"path": "ctx.request.csr_pem", "label": "CSR PEM", "sample": csr_info.get("csr_pem")},
                    {"path": "ctx.request.subject", "label": "CSR Subject", "sample": csr_info.get("subject")},
                    {"path": "ctx.request.common_name", "label": "Common Name", "sample": csr_info.get("common_name")},
                    {"path": "ctx.request.sans", "label": "SubjectAltNames", "sample": csr_info.get("sans")},
                    {"path": "ctx.request.public_key_type", "label": "Public Key Type", "sample": csr_info.get("public_key_type")},
                ],
            }
        )

        # Steps (always available)
        groups.append(
            {
                "name": "Steps",
                "vars": [
                    {"path": "ctx.steps.step_1", "label": "step_1", "sample": None},
                    {"path": "ctx.steps.step_1.status", "label": "step_1.status", "sample": None},
                    {"path": "ctx.steps.step_1.error", "label": "step_1.error", "sample": None},
                ],
            }
        )

        # Saved Vars
        groups.append(
            {
                "name": "Saved Vars",
                "vars": [
                    {"path": "ctx.vars.*", "label": "Saved Vars", "sample": None},
                ],
            }
        )

        return groups
