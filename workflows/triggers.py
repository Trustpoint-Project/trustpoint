# workflows/triggers.py

from dataclasses import dataclass
from typing import ClassVar, List


@dataclass(frozen=True)
class Trigger:
    protocol:  str
    operation: str


class Triggers:
    # —––– your single source of truth —–––
    est_simpleenroll   = Trigger('EST', 'simpleenroll')
    est_simplereenroll = Trigger('EST', 'simplereenroll')
    est_cacerts        = Trigger('EST', 'cacerts')
    est_csrattrs       = Trigger('EST', 'csrattrs')

    cmp_certRequest       = Trigger('CMP', 'certRequest')
    cmp_revocationRequest = Trigger('CMP', 'revocationRequest')

    scep_PKIOperation     = Trigger('SCEP', 'PKIOperation')

    @classmethod
    def all(cls) -> List[Trigger]:
        """Return every Trigger defined on this class."""
        return [v for v in vars(cls).values() if isinstance(v, Trigger)]

    @classmethod
    def protocols(cls) -> List[str]:
        """Unique list of protocol names."""
        return sorted({t.protocol for t in cls.all()})

    @classmethod
    def operations_for(cls, protocol: str) -> List[str]:
        """All operations available for a given protocol."""
        return [t.operation for t in cls.all() if t.protocol == protocol]
