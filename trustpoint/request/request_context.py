"""This module contains the RequestContext class for managing request-specific named attributes."""
from dataclasses import dataclass, fields
from typing import Any

from cryptography import x509
from cryptography.x509 import CertificateSigningRequest
from cryptography.x509.base import CertificateSigningRequestBuilder
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

    cert_requested: CertificateSigningRequest | CertificateSigningRequestBuilder | None = None

    est_username: str | None = None
    est_password: str | None = None
    cmp_shared_secret: str | None = None
    client_certificate: x509.Certificate | None = None
    client_intermediate_certificate: list[x509.Certificate] | None = None

    def to_dict(self) -> dict[str, Any]:
        """Serialize the context to a dictionary."""
        return {field.name: getattr(self, field.name) for field in fields(self)}

    def __str__(self) -> str:
        """String representation showing all context fields."""
        field_summary = ', '.join(f'{field.name}={getattr(self, field.name)}' for field in fields(self))
        return f'RequestContext({field_summary})'


    def __repr__(self) -> str:
        """Detailed representation for debugging."""
        return f'RequestContext(protocol={self.protocol}, operation={self.operation}, domain_str={self.domain_str})'

