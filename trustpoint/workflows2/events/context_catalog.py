# workflows2/events/context_catalog.py
from __future__ import annotations

from typing import Iterable

from workflows2.events.context import ContextVar


def ctx(*items: ContextVar) -> tuple[ContextVar, ...]:
    """
    Convenience helper to build tuples with nice formatting.
    """
    return tuple(items)


def merge(*groups: Iterable[ContextVar]) -> tuple[ContextVar, ...]:
    """
    Merge groups into one tuple, de-duplicating by `path` while preserving order.
    First occurrence wins.
    """
    out: list[ContextVar] = []
    seen: set[str] = set()
    for g in groups:
        for v in g:
            p = (v.path or "").strip()
            if not p or p in seen:
                continue
            seen.add(p)
            out.append(v)
    return tuple(out)


# --------------------------
# Common subsets
# --------------------------

DEVICE_CONTEXT = ctx(
    ContextVar("event.device.id", "uuid", "Device UUID"),
    ContextVar("event.device.common_name", "string", "Device common name"),
    ContextVar("event.device.serial_number", "string", "Device serial number"),
    ContextVar("event.device.domain_id", "int", "Domain ID"),
)

EST_CONTEXT = ctx(
    ContextVar("event.est.operation", "string", "EST operation name", example="simpleenroll"),
    ContextVar("event.est.fingerprint", "string", "CSR fingerprint (SHA-256)"),
    ContextVar("event.est.cert_profile", "string", "Requested certificate profile"),
    ContextVar("event.est.csr_pem", "string", "CSR PEM"),
)

# Optional if you want a stable place for source info inside templates.
# (Only include if you actually inject it into the template context root.)
SOURCE_CONTEXT = ctx(
    ContextVar("event.source.trustpoint", "bool", "Event emitted trustpoint-wide"),
    ContextVar("event.source.ca_id", "int", "CA id (if present)"),
    ContextVar("event.source.domain_id", "int", "Domain id (if present)"),
    ContextVar("event.source.device_id", "string", "Device id (if present)"),
)
