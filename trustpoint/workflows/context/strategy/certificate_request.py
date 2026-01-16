"""Context catalog strategy for certificate enrollment requests.

This module provides the wizard variable catalog for the `certificate_request`
handler, optionally specialized by protocol and operation.
"""

from __future__ import annotations

from typing import Any

from workflows.context.base import ContextStrategy
from workflows.context.registry import register

from .common import common_instance_group, common_workflow_group


@register
class CertificateRequestContextStrategy(ContextStrategy):
    """Context catalog strategy for the `certificate_request` handler."""
    handler = 'certificate_request'

    def get_design_time_groups(
        self,
        *,
        protocol: str | None = None,
        operation: str | None = None,
    ) -> list[dict[str, Any]]:
        """Return wizard variable groups for certificate_request.

        - "Common" vars are available regardless of protocol/operation
        - Protocol/operation groups are added conditionally
        """
        proto = (protocol or '').strip().lower()
        op = (operation or '').strip().lower()

        groups: list[dict[str, Any]] = []

        # ---- Common (handler-wide) ------------------------------------------
        groups.extend(
            [
                common_workflow_group(),
                common_instance_group(),
                {
                    'name': 'Device',
                    'vars': [
                        {'path': 'ctx.device.common_name', 'label': 'Device common name', 'sample': None},
                        {'path': 'ctx.device.serial_number', 'label': 'Device serial number', 'sample': None},
                        {'path': 'ctx.device.domain', 'label': 'Device domain', 'sample': None},
                        {'path': 'ctx.device.device_type', 'label': 'Device type', 'sample': None},
                        {'path': 'ctx.device.created_at', 'label': 'Device created at', 'sample': None},
                    ],
                },
                {
                    'name': 'Request',
                    'vars': [
                        {'path': 'ctx.request.protocol', 'label': 'Protocol', 'sample': proto or None},
                        {'path': 'ctx.request.operation', 'label': 'Operation', 'sample': op or None},
                        {'path': 'ctx.request.enrollment_request_id', 'label': 'Enrollment request ID', 'sample': None},
                        # Common CSR fields you already expose at runtime (context.py parses CSR)
                        {'path': 'ctx.request.csr_pem', 'label': 'CSR PEM', 'sample': None},
                        {'path': 'ctx.request.subject', 'label': 'CSR Subject', 'sample': None},
                        {'path': 'ctx.request.common_name', 'label': 'CSR Common Name', 'sample': None},
                        {'path': 'ctx.request.sans', 'label': 'CSR SANs', 'sample': None},
                        {'path': 'ctx.request.public_key_type', 'label': 'CSR Public Key Type', 'sample': None},
                        # If you expose template at runtime (you do for EnrollmentRequest)
                        {'path': 'ctx.request.template', 'label': 'Template', 'sample': None},
                    ],
                },
            ]
        )

        # ---- Protocol-specific ---------------------------------------------

        if proto == 'est':
            groups.append(
                {
                    'name': 'EST',
                    'vars': [
                        # These are examples / extension points.
                        # Add them later once you actually put them into ctx.request.est at runtime.
                        {'path': 'ctx.request.est.endpoint', 'label': 'EST endpoint', 'sample': None},
                        {'path': 'ctx.request.est.tls_client_auth', 'label': 'EST TLS client auth', 'sample': None},
                    ],
                }
            )

            # Operation-specific examples
            if op == 'simpleenroll':
                groups.append(
                    {
                        'name': 'EST • simpleenroll',
                        'vars': [
                            {
                                'path': 'ctx.request.est.simpleenroll.profile',
                                'label': 'Enrollment profile', 'sample': None
                            },
                        ],
                    }
                )
            elif op == 'simplereenroll':
                groups.append(
                    {
                        'name': 'EST • simplereenroll',
                        'vars': [
                            {
                                'path': 'ctx.request.est.simplereenroll.prev_cert_serial',
                                'label': 'Previous cert serial', 'sample': None
                            },
                        ],
                    }
                )
            elif op == 'csrattrs':
                groups.append(
                    {
                        'name': 'EST • csrattrs',
                        'vars': [
                            {'path': 'ctx.request.est.csrattrs.raw', 'label': 'CSR attrs (raw)', 'sample': None},
                            {'path': 'ctx.request.est.csrattrs.parsed', 'label': 'CSR attrs (parsed)', 'sample': None},
                        ],
                    }
                )

        elif proto == 'cmp':
            groups.append(
                {
                    'name': 'CMP',
                    'vars': [
                        # Example placeholders for later runtime ctx.request.cmp.*
                        {'path': 'ctx.request.cmp.transaction_id', 'label': 'CMP transaction ID', 'sample': None},
                        {'path': 'ctx.request.cmp.sender_nonce', 'label': 'CMP sender nonce', 'sample': None},
                        {'path': 'ctx.request.cmp.recipient_nonce', 'label': 'CMP recipient nonce', 'sample': None},
                        {'path': 'ctx.request.cmp.message_time', 'label': 'CMP message time', 'sample': None},
                        {'path': 'ctx.request.cmp.certreq_id', 'label': 'CMP certReqId', 'sample': None},
                    ],
                }
            )

            # Operation-specific examples
            if op == 'certrequest':
                groups.append(
                    {
                        'name': 'CMP • certRequest',
                        'vars': [
                            {'path': 'ctx.request.cmp.body_type', 'label': 'CMP body type', 'sample': None},
                        ],
                    }
                )
            elif op == 'revocationrequest':
                groups.append(
                    {
                        'name': 'CMP • revocationRequest',
                        'vars': [
                            {
                                'path': 'ctx.request.cmp.revocation.reason',
                                'label': 'Revocation reason', 'sample': None
                            },
                            {
                                'path': 'ctx.request.cmp.revocation.serial',
                                'label': 'Certificate serial', 'sample': None
                            },
                        ],
                    }
                )

        # You can add `elif proto == "scep": ...` later the same way.

        # ---- Saved Vars (always) -------------------------------------------
        groups.append(
            {
                'name': 'Saved Vars',
                'vars': [
                    {'path': 'ctx.vars.*', 'label': 'Saved Vars', 'sample': None},
                ],
            }
        )

        return groups

    # ---------------------------
    # Optional runtime catalog
    # ---------------------------
    # Only keep this if you still use instance-based catalog anywhere.
    # If not needed, delete this method.
    def get_groups(self, instance: Any) -> list[dict[str, Any]]:
        """Instance-aware catalog (optional).

        If your UI never asks for an instance-based catalog, remove this method.
        """
        # Keep it minimal or match your older implementation.
        return [
            common_workflow_group(instance),
            common_instance_group(instance),
            {'name': 'Saved Vars', 'vars': [{'path': 'ctx.vars.*', 'label': 'Saved Vars', 'sample': None}]},
        ]
