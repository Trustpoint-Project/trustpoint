# workflows/services/lookup.py
from __future__ import annotations

import hashlib
from typing import Any, Optional

from cryptography import x509

from workflows.models import WorkflowInstance, WorkflowDefinition


def fingerprint_from_csr_pem(csr_pem: str) -> str:
    """Compute stable fingerprint from CSR PEM (over CertificateRequestInfo)."""
    csr = x509.load_pem_x509_csr(csr_pem.encode())
    return hashlib.sha256(csr.tbs_certrequest_bytes).hexdigest()


def get_instance_by_fingerprint(
    definition: WorkflowDefinition,
    csr_pem: str,
) -> Optional[WorkflowInstance]:
    """Return the most relevant instance for this CSR/fingerprint (excluding rejected)."""
    fingerprint = fingerprint_from_csr_pem(csr_pem)
    return (
        WorkflowInstance.objects.filter(definition=definition, payload__fingerprint=fingerprint)
        .exclude(state=WorkflowInstance.STATE_REJECTED)
        .order_by('-updated_at')
        .first()
    )
