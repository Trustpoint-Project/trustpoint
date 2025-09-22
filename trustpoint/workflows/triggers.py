"""Trigger definitions for the workflows app.

This module centralizes the set of supported workflow triggers and provides
helpers to enumerate protocols and operations.
"""

from dataclasses import dataclass


@dataclass(frozen=True)
class Trigger:
    """Represents a single event trigger.

    Attributes:
        key: Internal name for the trigger.
        protocol: Protocol name (e.g., "EST", "CMP", "SCEP"); may be empty.
        operation: Protocol operation (e.g., "simpleenroll"); may be empty.
        handler: Service key that will process the trigger.
    """
    key: str
    protocol: str
    operation: str
    handler: str


class Triggers:
    """Central definition of all supported triggers in one place."""
    est_simpleenroll = Trigger(
        key='est_simpleenroll',
        protocol='EST',
        operation='simpleenroll',
        handler='certificate_request',
    )
    est_simplereenroll = Trigger(
        key='est_simplereenroll',
        protocol='EST',
        operation='simplereenroll',
        handler='certificate_request',
    )
    est_cacerts = Trigger(
        key='est_cacerts',
        protocol='EST',
        operation='cacerts',
        handler='certificate_issued',
    )
    est_csrattrs = Trigger(
        key='est_csrattrs',
        protocol='EST',
        operation='csrattrs',
        handler='certificate_request',
    )

    cmp_certrequest = Trigger(
        key='cmp_certrequest',
        protocol='CMP',
        operation='certRequest',
        handler='certificate_request',
    )
    cmp_revocationrequest = Trigger(
        key='cmp_revocationrequest',
        protocol='CMP',
        operation='revocationRequest',
        handler='certificate_request',
    )

    scep_pkioperation = Trigger(
        key='scep_pkioperation',
        protocol='SCEP',
        operation='PKIOperation',
        handler='certificate_request',
    )

    device_created = Trigger(
        key='device_created',
        protocol='',
        operation='',
        handler='device_created',
    )
    device_deleted = Trigger(
        key='device_deleted',
        protocol='',
        operation='',
        handler='device_deleted',
    )

    @classmethod
    def all(cls) -> list[Trigger]:
        """Return every Trigger defined on this class."""
        return [
            v for v in vars(cls).values()
            if isinstance(v, Trigger)
        ]

    @classmethod
    def protocols(cls) -> list[str]:
        """Unique list of non-empty protocol names."""
        return sorted({t.protocol for t in cls.all() if t.protocol})

    @classmethod
    def operations_for(cls, protocol: str) -> list[str]:
        """All operations available for a given protocol."""
        return [t.operation for t in cls.all() if t.protocol == protocol]
