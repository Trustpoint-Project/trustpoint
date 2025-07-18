"""This module contains the RequestContext class for managing request-specific named attributes."""
from dataclasses import asdict, dataclass
from typing import Any

from cryptography import x509
from cryptography.x509 import CertificateSigningRequest
from devices.models import DeviceModel
from django.http import HttpRequest
from pki.models import DomainModel
from pyasn1_modules.rfc4210 import PKIMessage


@dataclass
class RequestContext:
    """Container for managing request-specific named attributes."""
    raw_message: HttpRequest | None = None
    parsed_message: CertificateSigningRequest | PKIMessage | None = None
    operation: str | None = None
    protocol: str | None = None
    certificate_template: str | None = None
    response_format: str | None = None
    est_encoding: str | None = None

    domain_str: str | None = None
    domain: DomainModel | None = None
    device: DeviceModel | None = None

    cert_requested: CertificateSigningRequest | None = None

    est_username: str | None = None
    est_password: str | None = None
    cmp_shared_secret: str | None = None
    client_certificate: x509.Certificate | None = None
    client_intermediate_certificate: list[x509.Certificate] | None = None

    def to_dict(self) -> dict[str, Any]:
        """Serialize the context to a dictionary."""
        return asdict(self)

    def clear(self) -> None:
        """Reset all attributes to default (None)."""
        for field in self.__dataclass_fields__:
            setattr(self, field, None)

    def __str__(self) -> str:
        """String representation showing key context information."""
        non_none_fields = self.get_non_none_fields()
        field_summary = ", ".join(f"{k}={v}" for k, v in non_none_fields.items())
        return f"RequestContext({field_summary})"

    def __repr__(self) -> str:
        """Detailed representation for debugging."""
        return f"RequestContext(protocol={self.protocol}, operation={self.operation}, domain_str={self.domain_str})"

