"""This module contains the RequestContext class for managing request-specific named attributes."""
from __future__ import annotations

from dataclasses import dataclass, fields
from typing import TYPE_CHECKING, Any, TypeVar

from cryptography import x509
from django.http import HttpResponse

from trustpoint.logger import LoggerMixin

if TYPE_CHECKING:
    from cryptography.x509 import CertificateSigningRequest
    from cryptography.x509.base import CertificateBuilder
    from django.http import HttpRequest
    from pyasn1_modules.rfc4210 import PKIMessage  # type: ignore[import-untyped]

    from cmp.util import PKIFailureInfo
    from devices.models import DeviceModel, IssuedCredentialModel
    from pki.models import CertificateProfileModel, CredentialModel, DomainModel, TruststoreModel
    from workflows.events import Event
    from workflows.models import EnrollmentRequest

# Request context classes follow the naming convention of <Protocol><Operation>RequestContext

RCT = TypeVar('RCT', bound='BaseRequestContext')

@dataclass(kw_only=True)
class BaseRequestContext(LoggerMixin):
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

    # TODO: This should be refactored into the overall Request Context  # noqa: FIX002, TD002
    event: Event | None = None

    def error(self, ext_msg: str | bytes |None,
              http_status: int | None = None,
              cmp_code: PKIFailureInfo | None = None) -> None:
        """Set an error message in the context."""
        if isinstance(self, HttpBaseRequestContext):
            self.http_response_content = ext_msg
            self.http_response_status = http_status
        if isinstance(self, CmpBaseRequestContext):
            self.error_details = ext_msg
            self.error_code = cmp_code

    def to_dict(self) -> dict[str, Any]:
        """Serialize the context to a dictionary."""
        return {field.name: getattr(self, field.name) for field in fields(self)}

    def to_http_response(self) -> HttpResponse:
        """Convert the context's HTTP response attributes to a Django HttpResponse."""
        if not isinstance(self, HttpBaseRequestContext):
            exc_msg = 'to_http_response can only be called on HttpBaseRequestContext instances.'
            raise TypeError(exc_msg)
        return HttpResponse(content=self.http_response_content or b'',
                            status=self.http_response_status or 500,
                            content_type=self.http_response_content_type or 'text/plain')

    def narrow(self, child_cls: type[RCT], **extra: Any) -> RCT:
        """Create a new request context of a more specific subclass, copying existing attributes."""
        data = self.to_dict()
        data = {k: v for k, v in data.items() if hasattr(child_cls, k)}
        return child_cls(**data, **extra)

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

@dataclass(kw_only=True)
class BaseCertificateRequestContext(BaseRequestContext):
    """Shared context for all certificate request operations."""
    cert_requested: CertificateSigningRequest | CertificateBuilder | None = None
    cert_profile_str: str | None = None
    cert_requested_profile_validated: CertificateBuilder | None = None
    issued_certificate: x509.Certificate | None = None

    certificate_profile_model: CertificateProfileModel | None = None

    # Flag to allow CA certificate requests (e.g., for Issuing CA certificate enrollment)
    allow_ca_certificate_request: bool = False

    # Request data for building CSR
    request_data: dict[str, Any] | None = None
    validated_request_data: dict[str, Any] | None = None

    # TODO: This should be refactored into the overall Request Context  # noqa: FIX002, TD002
    enrollment_request: EnrollmentRequest | None = None
    event: Event | None = None


@dataclass(kw_only=True)
class BaseRevocationRequestContext(BaseRequestContext):
    """Shared context for all revocation request operations."""
    cert_serial_number: str | None = None
    credential_to_revoke: IssuedCredentialModel | None = None
    revocation_reason: x509.ReasonFlags = x509.ReasonFlags.unspecified


@dataclass(kw_only=True)
class HttpBaseRequestContext(BaseRequestContext):
    """Shared context for all protocols that use HTTP(s) for message transfer."""
    raw_message: HttpRequest | None = None

    http_response_status: int | None = None
    # consider adding http_response_headers: dict[str, str] | None = None
    http_response_content: bytes | str | None = None
    http_response_content_type: str | None = None


@dataclass(kw_only=True)
class EstBaseRequestContext(HttpBaseRequestContext):
    """Shared context for all EST requests.

    Supports both EST server functionality (receiving requests) and EST client
    functionality (sending requests to external EST servers).
    """
    # Server-side fields
    parsed_message: CertificateSigningRequest | None = None
    est_encoding: str | None = None
    est_username: str | None = None
    est_password: str | None = None

    # Client-side fields
    est_server_host: str | None = None
    est_server_port: int | None = None
    est_server_path: str | None = None
    est_server_truststore: TruststoreModel | None = None

@dataclass(kw_only=True)
class CmpBaseRequestContext(HttpBaseRequestContext):
    """Shared context for all CMP requests.

    Supports both CMP server functionality (receiving requests) and CMP client
    functionality (sending requests to external CMP servers).
    """
    # Server-side fields
    parsed_message: PKIMessage | None = None
    cmp_shared_secret: str | None = None
    error_code: PKIFailureInfo | None = None
    error_details: str | None = None

    # Client-side fields
    cmp_server_host: str | None = None
    cmp_server_port: int | None = None
    cmp_server_path: str | None = None
    cmp_server_truststore: TruststoreModel | None = None


@dataclass(kw_only=True)
class RestBaseRequestContext(HttpBaseRequestContext):
    """Shared context for all REST API requests."""


@dataclass(kw_only=True)
class EstCertificateRequestContext(EstBaseRequestContext, BaseCertificateRequestContext):
    """EST context for certificate enrollment requests."""

class EstRevocationRequestContext(EstBaseRequestContext, BaseRevocationRequestContext):
    """EST context for certificate revocation requests."""

@dataclass(kw_only=True)
class CmpCertificateRequestContext(CmpBaseRequestContext, BaseCertificateRequestContext):
    """CMP context for certificate enrollment requests (IR/CR)."""

class CmpRevocationRequestContext(CmpBaseRequestContext, BaseRevocationRequestContext):
    """CMP context for certificate revocation requests (RR)."""
