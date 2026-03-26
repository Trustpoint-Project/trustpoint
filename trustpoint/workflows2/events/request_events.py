"""Canonical request-pipeline events owned by Workflow 2."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Event:
    """Describe one request-pipeline event emitted into workflows2."""

    key: str
    protocol: str
    operation: str
    handler: str


class Events:
    """Central definition of request events supported by workflows2."""

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

    rest_enroll = Event(
        key='rest_enroll',
        protocol='rest',
        operation='enroll',
        handler='certificate_request',
    )

    rest_reenroll = Event(
        key='rest_reenroll',
        protocol='rest',
        operation='reenroll',
        handler='certificate_request',
    )

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
        """Return every request event defined on this class."""
        return [value for value in vars(cls).values() if isinstance(value, Event)]

    @classmethod
    def protocols(cls) -> list[str]:
        """Return the unique request protocols."""
        return sorted({event.protocol for event in cls.all() if event.protocol})

    @classmethod
    def operations_for(cls, protocol: str) -> list[str]:
        """Return all operations for the given protocol."""
        normalized_protocol = (protocol or '').strip().lower()
        return sorted(
            {
                event.operation
                for event in cls.all()
                if event.protocol == normalized_protocol and event.operation
            }
        )
