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
    from trustpoint_core.serializer import PrivateKeySerializer

    from cmp.util import PKIFailureInfo
    from devices.models import DeviceModel
    from pki.models import CertificateProfileModel, CredentialModel, DomainModel, IssuedCredentialModel, TruststoreModel
    from workflows2.events.request_events import Event
    from workflows2.services.dispatch import DispatchOutcome

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

    # The authenticated user who triggered this request, if applicable (e.g. manual web UI issuance).
    # None for machine-to-machine protocol flows (CMP, EST).
    actor: Any | None = None

    # TODO: This should be refactored into the overall Request Context  # noqa: FIX002, TD002
    event: Event | None = None
    event_payload: dict[str, Any] | None = None
    workflow2_outcome: DispatchOutcome | None = None

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
        response = HttpResponse(content=self.http_response_content or b'',
                                status=self.http_response_status or 500,
                                content_type=self.http_response_content_type or 'text/plain')
        if self.http_response_headers:
            for header_name, header_value in self.http_response_headers.items():
                response[header_name] = header_value
        return response

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
    issued_certificate_chain: list[x509.Certificate] | None = None

    certificate_profile_model: CertificateProfileModel | None = None

    # Flag to allow CA certificate requests (e.g., for Issuing CA certificate enrollment)
    allow_ca_certificate_request: bool = False

    # Request data for building CSR
    request_data: dict[str, Any] | None = None
    validated_request_data: dict[str, Any] | None = None

    event: Event | None = None

@dataclass(kw_only=True)
class BaseCredentialRequestContext(BaseCertificateRequestContext):
    """Shared context for all credential request (keypair generated by Trustpoint) operations."""
    private_key: PrivateKeySerializer | None = None
    issued_credential: IssuedCredentialModel | None = None


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
    http_response_headers: dict[str, str] | None = None
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

    # Client certificate (mTLS) authentication — used instead of username/password
    est_client_cert_pem: str | None = None
    est_client_key_pem: str | None = None

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
    implicit_confirm: bool = False

    # Client-side fields
    cmp_server_host: str | None = None
    cmp_server_port: int | None = None
    cmp_server_path: str | None = None
    cmp_server_truststore: TruststoreModel | None = None


@dataclass(kw_only=True)
class RestBaseRequestContext(HttpBaseRequestContext):
    """Shared context for all REST API requests."""

    rest_username: str | None = None
    rest_password: str | None = None


@dataclass(kw_only=True)
class RestCertificateRequestContext(RestBaseRequestContext, BaseCertificateRequestContext):
    """REST context for certificate enrollment requests."""


@dataclass(kw_only=True)
class ManualBaseRequestContext(BaseRequestContext):
    """Shared context for all manually triggered requests (e.g., from the web UI)."""
    protocol: str = 'manual'


@dataclass(kw_only=True)
class EstCertificateRequestContext(EstBaseRequestContext, BaseCertificateRequestContext):
    """EST context for certificate enrollment requests."""

@dataclass(kw_only=True)
class EstRevocationRequestContext(EstBaseRequestContext, BaseRevocationRequestContext):
    """EST context for certificate revocation requests."""

@dataclass(kw_only=True)
class CmpCertificateRequestContext(CmpBaseRequestContext, BaseCertificateRequestContext):
    """CMP context for certificate enrollment requests (IR/CR)."""

@dataclass(kw_only=True)
class CmpRevocationRequestContext(CmpBaseRequestContext, BaseRevocationRequestContext):
    """CMP context for certificate revocation requests (RR)."""

@dataclass(kw_only=True)
class CmpCertConfRequestContext(CmpBaseRequestContext, BaseRevocationRequestContext):
    """CMP context for certificate confirmation requests (certConf).

    Holds the parsed certHash, certReqId, and optional statusInfo from the
    certConf body as defined in RFC 4210 Section 5.3.18 and profiled by
    RFC 9483 Section 4.1.1.

    Also inherits :class:`BaseRevocationRequestContext` so that the
    ``credential_to_revoke`` field can be populated by the authorization
    component when the EE signals rejection (cert_conf_status == 2), enabling
    the operation processor to revoke the certificate via the standard
    revocation pipeline.
    """

    cert_hash: bytes | None = None
    """DER-encoded hash over the confirmed certificate (certHash field)."""

    cert_req_id: int | None = None
    """certReqId from the CertStatus structure (MUST be 0 per RFC 9483)."""

    cert_conf_status: int | None = None
    """PKIStatus from statusInfo, if present. 0=accepted, 2=rejection."""

    cert_conf_status_string: str | None = None
    """Human-readable statusString from statusInfo, if present."""


@dataclass(kw_only=True)
class ManualCredentialRequestContext(ManualBaseRequestContext, BaseCredentialRequestContext):
    """Manual context for credential requests triggered from the web UI."""
