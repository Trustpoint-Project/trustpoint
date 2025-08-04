# workflows/triggers.py

from dataclasses import dataclass
from typing import Any


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

    cmp_certrequest       = Trigger('CMP', 'certRequest')
    cmp_revocationrequest = Trigger('CMP', 'revocationRequest')

    scep_pkioperation     = Trigger('SCEP', 'PKIOperation')

    @classmethod
    def all(cls) -> list[Trigger]:
        """Return every Trigger defined on this class."""
        return [v for v in vars(cls).values() if isinstance(v, Trigger)]

    @classmethod
    def protocols(cls) -> list[str]:
        """Unique list of protocol names."""
        return sorted({t.protocol for t in cls.all()})

    @classmethod
    def operations_for(cls, protocol: str) -> list[str]:
        """All operations available for a given protocol."""
        return [t.operation for t in cls.all() if t.protocol == protocol]


RAW_EMAIL_TEMPLATES = [
    "device_onboarded",
    "cert_expiry_warning",
    "cert_expired",
    "cert_revoked",
    "user_welcome",
    "password_reset",
]

EMAIL_TEMPLATES: list[dict[str, str]] = [
    {
        "value": t,
        "label": " ".join(word.capitalize() for word in t.split("_"))
    }
    for t in RAW_EMAIL_TEMPLATES
]

# 2) Map each workflow node type to the list of parameters the wizard should render.
#    For now, only Email has inputs; others are empty lists.
STEP_PARAM_DEFS: dict[str, list[dict[str, Any]]] = {
    'Approval': [],
    'Email': [
        {
            'name': 'template',
            'label': 'Email Template',
            'type': 'select',
            'options': EMAIL_TEMPLATES,
        },
        {
            'name': 'recipients',
            'label': 'Recipients (comma-separated)',
            'type': 'text',
        },
    ],
    'Webhook': [],
    'Timer': [],
    'Condition': [],
    'IssueCertificate': [],
}
