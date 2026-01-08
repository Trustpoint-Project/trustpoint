"""Event definitions for the workflows app.

This module centralizes the set of supported workflow events and provides
helpers to enumerate protocols and operations.
"""

from dataclasses import dataclass


@dataclass(frozen=True)
class Event:
    """Represents a single event.

    Attributes:
        key: Internal name for the event.
        protocol: Protocol name (e.g., "EST", "CMP", "SCEP"); may be empty.
        operation: Protocol operation (e.g., "simpleenroll"); may be empty.
        handler: Service key that will process the event.
    """
    key: str
    protocol: str
    operation: str
    handler: str


class Events:
    """Central definition of all supported events in one place."""
    est_simpleenroll = Event(
        key='est_simpleenroll',
        protocol='est',
        operation='simpleenroll',
        handler='certificate_request',
    )

    est_simplereenroll = Event(
        key='est_simplereenroll',
        protocol='EST',
        operation='simplereenroll',
        handler='certificate_request',
    )
    """

    est_cacerts = Event(
        key='est_cacerts',
        protocol='EST',
        operation='',
        handler='certificate_issued',
    )

    est_csrattrs = Event(
        key='est_csrattrs',
        protocol='EST',
        operation='csrattrs',
        handler='certificate_request',
    )

    cmp_certrequest = Event(
        key='cmp_certrequest',
        protocol='CMP',
        operation='certRequest',
        handler='certificate_request',
    )

    cmp_revocationrequest = Event(
        key='cmp_revocationrequest',
        protocol='CMP',
        operation='revocationRequest',
        handler='certificate_request',
    )

    scep_pkioperation = Event(
        key='scep_pkioperation',
        protocol='SCEP',
        operation='PKIOperation',
        handler='certificate_request',
    )"""

    device_created = Event(
        key='device_created',
        protocol='device',
        operation='created',
        handler='device_action',
    )

    device_onboarded = Event(
        key='device_onboarded',
        protocol='device',
        operation='onboarded',
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
        """Return every Event defined on this class.

        Returns:
            list[Event]: All Event instances defined as class attributes.
        """
        return [v for v in vars(cls).values() if isinstance(v, Event)]

    @classmethod
    def protocols(cls) -> list[str]:
        """Return the unique list of non-empty protocol names.

        Returns:
            list[str]: Sorted list of protocol identifiers used by defined events.
        """
        return sorted({e.protocol for e in cls.all() if e.protocol})

    @classmethod
    def operations_for(cls, protocol: str) -> list[str]:
        """Return all operations available for a given protocol.

        Args:
            protocol: Protocol identifier (e.g. ``"est"``).

        Returns:
            list[str]: Operations associated with the given protocol.
        """
        return [e.operation for e in cls.all() if e.protocol == protocol]
