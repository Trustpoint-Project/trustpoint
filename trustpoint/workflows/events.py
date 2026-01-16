"""Event definitions for the workflows app.

This module centralizes the supported workflow events and provides helpers to
enumerate protocols and operations.

Normalization rules:
- protocol and operation are stored in lowercase.
- callers of operations_for() are normalized to lowercase.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Event:
    """Represents a single event.

    Attributes:
        key: Internal name for the event.
        protocol: Protocol or source namespace (lowercase).
        operation: Operation within the protocol namespace (lowercase).
        handler: Handler key used by the routing/handler layer.
    """

    key: str
    protocol: str
    operation: str
    handler: str


class Events:
    """Central definition of all supported events in one place."""

    # EST
    est_simpleenroll = Event(
        key='est_simpleenroll',
        protocol='est',
        operation='simpleenroll',
        handler='certificate_request',
    )

    est_simplereenroll = Event(
        key='est_simplereenroll',
        protocol='est',
        operation='simplereenroll',
        handler='certificate_request',
    )

    # Device lifecycle
    device_created = Event(
        key='device_created',
        protocol='device',
        operation='created',
        handler='device_action',
    )

    device_domain_changed = Event(
        key='device_domain_changed',
        protocol='device',
        operation='domain changed',
        handler='device_action',
    )

    device_deleted = Event(
        key='device_deleted',
        protocol='device',
        operation='deleted',
        handler='device_action',
    )

    @classmethod
    def all(cls) -> list[Event]:
        """Return every Event defined on this class."""
        return [v for v in vars(cls).values() if isinstance(v, Event)]

    @classmethod
    def protocols(cls) -> list[str]:
        """Return the unique list of non-empty protocol names."""
        return sorted({e.protocol for e in cls.all() if e.protocol})

    @classmethod
    def operations_for(cls, protocol: str) -> list[str]:
        """Return all operations available for a given protocol."""
        p = (protocol or '').strip().lower()
        return sorted({e.operation for e in cls.all() if e.protocol == p and e.operation})
