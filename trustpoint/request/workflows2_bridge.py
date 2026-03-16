from __future__ import annotations

import hashlib
from typing import Any

from cryptography.x509 import CertificateSigningRequest

from workflows2.events.triggers import Triggers
from workflows2.services.dispatch import EventSource, WorkflowDispatchService


def emit_est_simpleenroll(
    *,
    csr: CertificateSigningRequest,
    domain_id: int | None,
    device_id: str | None,
    ca_id: int | None,
    cert_profile: str | None,
    extra: dict[str, Any] | None = None,
) -> tuple[str, Any]:
    """Returns (run_status, run_or_instances) depending on how you want to structure it.

    For now emit_event returns instances; the run is created inside the service.
    """
    fingerprint = hashlib.sha256(csr.tbs_certrequest_bytes).hexdigest()

    event = {
        "est": {
            "operation": "simpleenroll",
            "fingerprint": fingerprint,
            "cert_profile": cert_profile or "",
            "csr_pem": csr.public_bytes(encoding=csr.public_bytes.__annotations__.get("encoding")).decode("utf-8")  # you likely already have PEM elsewhere; replace
        },
        **(extra or {}),
    }

    source = EventSource(
        trustpoint=False,
        ca_id=ca_id,
        domain_id=domain_id,
        device_id=device_id,
    )

    instances = WorkflowDispatchService().emit_event(
        on=Triggers.EST_SIMPLEENROLL,
        event=event,
        source=source,
        initial_vars={},
        idempotency_key=fingerprint,  # ✅ perfect for polling/idempotent semantics
    )
    return ("instances", instances)
