import uuid
from typing import Any, Optional

from django.dispatch import Signal, receiver

from workflows.services.orchestrator import handle_certificate_request

# A generic signal with no providing_args (Django ≥4.0)
certificate_request = Signal()


@receiver(certificate_request)
def on_certificate_request(
    sender: Any,
    protocol: str,
    operation: str,
    ca_id: uuid.UUID,
    domain_id: Optional[uuid.UUID],
    device_id: Optional[uuid.UUID],
    payload: dict[str, Any],
    **kwargs: Any,
) -> None:
    """Handle incoming certificate‐request events and start workflows.

    Args:
        sender: The sender of the signal.
        protocol: One of 'EST', 'CMP', 'SCEP', etc.
        operation: The operation name e.g. 'simpleenroll', 'certRequest'.
        ca_id: UUID of the issuing CA.
        domain_id: UUID of the device's domain (if any).
        device_id: UUID of the requesting device (if any).
        payload: Arbitrary context (CSR, requestor username, etc.).
    """
    handle_certificate_request(
        protocol=protocol,
        operation=operation,
        ca_id=ca_id,
        domain_id=domain_id,
        device_id=device_id,
        payload=payload,
    )
