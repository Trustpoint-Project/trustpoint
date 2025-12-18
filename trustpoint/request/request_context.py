"""This module contains the RequestContext class for managing request-specific named attributes."""
from __future__ import annotations

from dataclasses import dataclass, fields
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from cryptography import x509
    from cryptography.x509 import CertificateSigningRequest
    from cryptography.x509.base import CertificateBuilder
    from django.http import HttpRequest
    from pyasn1_modules.rfc4210 import PKIMessage  # type: ignore[import-untyped]

    from devices.models import DeviceModel, IssuedCredentialModel
    from pki.models import CertificateProfileModel, CredentialModel, DomainModel
    from workflows.events import Event
    from workflows.models import EnrollmentRequest

# Request context classes follow the naming convention of <Protocol><Operation>RequestContext

@dataclass
class BaseRequestContext:
    """Base class for all specific request context classes."""
    operation: str | None = None
    protocol: str | None = None

    parsed_message: CertificateSigningRequest | PKIMessage | None = None

    domain_str: str | None = None
    domain: DomainModel | None = None
    device: DeviceModel | None = None

    owner_credential: CredentialModel | None = None
    issuer_credential: CredentialModel | None = None

    client_certificate: x509.Certificate | None = None
    client_intermediate_certificate: list[x509.Certificate] | None = None

    def to_dict(self) -> dict[str, Any]:
        """Serialize the context to a dictionary."""
        return {field.name: getattr(self, field.name) for field in fields(self)}

    def clear(self) -> None:
        """Reset all attributes to None."""
        for field in fields(self):
            setattr(self, field.name, None)

    def __str__(self) -> str:
        """String representation showing all context fields."""
        field_summary = ', '.join(f'{field.name}={getattr(self, field.name)}' for field in fields(self))
        return f'{self.__class__.__name__}({field_summary})'

    def __repr__(self) -> str:
        """Detailed representation for debugging."""
        return (f'{self.__class__.__name__}(protocol={self.protocol}, '
                f'operation={self.operation}, domain_str={self.domain_str})')

class BaseCertificateRequestContext(BaseRequestContext):
    """Shared context for all certificate request operations."""
    cert_requested: CertificateSigningRequest | CertificateBuilder | None = None
    cert_profile_str: str | None = None
    cert_requested_profile_validated: CertificateBuilder | None = None
    issued_certificate: x509.Certificate | None = None

    certificate_profile_model: CertificateProfileModel | None = None

    # TODO: These two should be refactored into the overall Request Context  # noqa: FIX002, TD002
    enrollment_request: EnrollmentRequest | None = None
    event: Event | None = None


class BaseRevocationRequestContext(BaseRequestContext):
    """Shared context for all revocation request operations."""
    credential_to_revoke: IssuedCredentialModel | None = None

class HttpBaseRequestContext(BaseRequestContext):
    """Shared context for all protocols that use HTTP(s) for message transfer."""
    raw_message: HttpRequest | None = None

    http_response_status: int | None = None
    # consider adding http_response_headers: dict[str, str] | None = None
    http_response_content: bytes | str | None = None
    http_response_content_type: str | None = None

class EstBaseRequestContext(HttpBaseRequestContext):
    """Shared context for all EST requests."""
    parsed_message: CertificateSigningRequest | None = None
    est_encoding: str | None = None
    est_username: str | None = None
    est_password: str | None = None

class CmpBaseRequestContext(HttpBaseRequestContext):
    """Shared context for all CMP requests."""
    parsed_message: PKIMessage | None = None
    cmp_shared_secret: str | None = None

class RestBaseRequestContext(HttpBaseRequestContext):
    """Shared context for all REST API requests."""

class EstCertificateRequestContext(EstBaseRequestContext, BaseCertificateRequestContext):
    """EST context for certificate enrollment requests."""

class EstRevocationRequestContext(EstBaseRequestContext, BaseRevocationRequestContext):
    """EST context for certificate revocation requests."""

class CmpCertificateRequestContext(CmpBaseRequestContext, BaseCertificateRequestContext):
    """CMP context for certificate enrollment requests (IR/CR)."""

class CmpRevocationRequestContext(CmpBaseRequestContext, BaseRevocationRequestContext):
    """CMP context for certificate revocation requests (RR)."""
