# Copyright (c) 2025 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Provides the `HttpRequestValidator` class for validating HTTP requests."""

import base64
import contextlib
import ipaddress
import itertools
import urllib.parse
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

from cryptography import x509
from django.conf import settings

from request.request_context import HttpBaseRequestContext
from trustpoint.logger import LoggerMixin

if TYPE_CHECKING:
    from django.http import HttpRequest


class ValidationComponent(ABC):
    """Abstract base class to represent a component in composite validation."""

    @abstractmethod
    def validate(self, context: HttpBaseRequestContext) -> None:
        """Execute validation logic and enrich context."""


class TrustedProxyHeadersValidation(ValidationComponent, LoggerMixin):
    """Reject proxy-derived identity headers from untrusted network peers.

    The reverse proxy is a security boundary: TLS client-certificate and
    forwarding headers are authoritative only when the direct TCP peer is a
    configured trusted proxy.  The default only trusts loopback, which keeps
    development mode usable while failing closed for container deployments
    until their proxy subnet/address is configured explicitly.
    """

    def __init__(self) -> None:
        """Initialize the trusted proxy headers validation component."""
        super().__init__()

        self._SENSITIVE_EXACT = {
            'HTTP_SSL_CLIENT_CERT',
            'HTTP_X_FORWARDED_FOR',
            'HTTP_X_REAL_IP',
            'HTTP_X_EST_TLS_UNIQUE',
            'HTTP_X_EST_TLS_UNIQUE_SUPPORTED',
            'HTTP_X_EST_TLS_PROTOCOL',
        }

    @staticmethod
    def _trusted_networks() -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
        configured = getattr(settings, 'TRUSTPOINT_TRUSTED_PROXY_IPS', ('127.0.0.1', '::1'))
        if isinstance(configured, str):
            configured = [item.strip() for item in configured.split(',') if item.strip()]
        return [ipaddress.ip_network(str(value), strict=False) for value in configured]

    def _has_sensitive_headers(self, meta: dict[str, object]) -> bool:
        if any(meta.get(name) not in (None, '') for name in self._SENSITIVE_EXACT):
            return True
        return any(
            key.startswith(('HTTP_SSL_CLIENT_CERT_CHAIN_', 'SSL_CLIENT_CERT_CHAIN_'))
            for key, value in meta.items()
            if value not in (None, '')
        )

    def validate(self, context: HttpBaseRequestContext) -> None:
        """Validate that security-sensitive proxy headers came from a trusted peer."""
        if context.raw_message is None:
            msg = 'Raw message is missing from the context.'
            raise ValueError(msg)
        meta = context.raw_message.META
        if not self._has_sensitive_headers(meta):
            return

        self.validate_request_peer(context.raw_message)

    def validate_request_peer(self, request: 'HttpRequest') -> None:
        """Require an explicitly trusted TCP peer for proxy assertions."""
        meta = request.META

        remote_addr = str(meta.get('REMOTE_ADDR') or '').strip()
        if not remote_addr:
            msg = 'REMOTE_ADDR is required when proxy-derived security headers are present.'
            raise ValueError(msg)
        try:
            peer = ipaddress.ip_address(remote_addr)
        except ValueError as exc:
            msg = 'REMOTE_ADDR is invalid.'
            raise ValueError(msg) from exc

        if not any(peer in network for network in self._trusted_networks()):
            self.logger.warning(
                'Rejected proxy-derived identity headers from untrusted peer %s',
                remote_addr,
            )
            msg = 'Proxy-derived identity headers were received from an untrusted peer.'
            raise ValueError(msg)


class PayloadSizeValidation(ValidationComponent, LoggerMixin):
    """Validate payload size."""

    def __init__(self, max_payload_size: int) -> None:
        """Initialize with the maximum accepted request size in bytes."""
        self.max_payload_size = max_payload_size

    def validate(self, context: HttpBaseRequestContext) -> None:
        """Validate the HTTP request payload size."""
        if context.raw_message is None:
            msg = 'Raw message is missing from the context.'
            raise ValueError(msg)
        if not hasattr(context.raw_message, 'body') or not context.raw_message.body:
            msg = 'Raw message is missing body.'
            raise ValueError(msg)
        payload_size = len(context.raw_message.body)
        if payload_size > self.max_payload_size:
            msg = f'Payload size exceeds maximum allowed size of {self.max_payload_size} bytes.'
            raise ValueError(msg)
        self.logger.debug(
            'Payload size validation successful: %d bytes (limit: %d bytes)',
            payload_size,
            self.max_payload_size,
        )


class ContentTypeValidation(ValidationComponent, LoggerMixin):
    """Validate request content type."""

    def __init__(self, expected_content_type: str) -> None:
        """Initialize with the required request Content-Type."""
        self.expected_content_type = expected_content_type

    def validate(self, context: HttpBaseRequestContext) -> None:
        """Validate the request Content-Type header."""
        if context.raw_message is None:
            msg = 'Raw message is missing from the context.'
            raise ValueError(msg)
        if not hasattr(context.raw_message, 'headers') or not context.raw_message.headers:
            msg = 'Raw message is missing headers.'
            raise ValueError(msg)
        content_type = context.raw_message.headers.get('Content-Type')
        if not content_type:
            msg = "Missing 'Content-Type' header."
            raise ValueError(msg)
        if content_type != self.expected_content_type:
            msg = f"Invalid 'Content-Type' header '{content_type}'. Expected '{self.expected_content_type}'."
            raise ValueError(msg)


class AcceptHeaderValidation(ValidationComponent, LoggerMixin):
    """Validate the Accept header."""

    def __init__(self, allowed_content_types: list[str]) -> None:
        """Initialize with the allowed response media types."""
        self.allowed_content_types = allowed_content_types

    def validate(self, context: HttpBaseRequestContext) -> None:
        """Validate the optional Accept header."""
        if context.raw_message is None:
            msg = 'Raw message is missing from the context.'
            raise ValueError(msg)
        if not hasattr(context.raw_message, 'headers') or not context.raw_message.headers:
            msg = 'Raw message is missing headers.'
            raise ValueError(msg)
        accept_header = context.raw_message.headers.get('Accept')
        if not accept_header:
            return
        accepted_types = [content_type.strip() for content_type in accept_header.split(',')]
        if not any(allowed_type in accepted_types for allowed_type in self.allowed_content_types):
            msg = (
                f"The provided 'Accept' header '{accept_header}' does not match any of the allowed types: "
                f'{", ".join(self.allowed_content_types)}.'
            )
            raise ValueError(msg)


class ClientCertificateValidation(ValidationComponent, LoggerMixin):
    """Parse a TLS client certificate injected by the trusted reverse proxy."""

    def validate(self, context: HttpBaseRequestContext) -> None:
        """Load the trusted proxy client-certificate header into the request context."""
        if context.raw_message is None:
            msg = 'Raw message is missing from the context.'
            raise ValueError(msg)
        if not hasattr(context.raw_message, 'META') or not context.raw_message.META:
            return

        ssl_client_cert = context.raw_message.META.get('HTTP_SSL_CLIENT_CERT')
        if ssl_client_cert is None or not str(ssl_client_cert).strip():
            return

        try:
            ssl_client_cert_unquoted = urllib.parse.unquote(str(ssl_client_cert))
            client_certificate = x509.load_pem_x509_certificate(ssl_client_cert_unquoted.encode('utf-8'))
            context.client_certificate = client_certificate
            subject_cn = 'unknown'
            with contextlib.suppress(IndexError, AttributeError):
                cn_value = client_certificate.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
                subject_cn = cn_value if isinstance(cn_value, str) else cn_value.decode('utf-8')
            self.logger.debug('Loaded trusted proxy client certificate for subject %s', subject_cn)
        except Exception as exc:
            msg = f'Invalid HTTP_SSL_CLIENT_CERT header: {exc}'
            raise ValueError(msg) from exc


class IntermediateCertificatesValidation(ValidationComponent, LoggerMixin):
    """Parse intermediate CA certificates injected by the trusted reverse proxy."""

    def validate(self, context: HttpBaseRequestContext) -> None:
        """Load trusted proxy certificate-chain headers into the request context."""
        if context.raw_message is None:
            msg = 'Raw message is missing from the context.'
            raise ValueError(msg)

        intermediate_cas: list[x509.Certificate] = []
        for i in itertools.count():
            ca = context.raw_message.META.get(f'HTTP_SSL_CLIENT_CERT_CHAIN_{i}') or context.raw_message.META.get(
                f'SSL_CLIENT_CERT_CHAIN_{i}'
            )
            if not ca:
                break
            try:
                ca_text = urllib.parse.unquote(str(ca))
                intermediate_cas.append(x509.load_pem_x509_certificate(ca_text.encode('utf-8')))
            except Exception as exc:
                msg = f'Invalid SSL client certificate chain entry {i}: {exc}'
                raise ValueError(msg) from exc

        context.client_intermediate_certificate = intermediate_cas or None


class ContentTransferEncodingValidation(ValidationComponent, LoggerMixin):
    """Validate the Content-Transfer-Encoding header."""

    def validate(self, context: HttpBaseRequestContext) -> None:
        """Validate and decode Base64 request bodies when requested."""
        if context.raw_message is None:
            msg = 'Raw message is missing from the context.'
            raise ValueError(msg)
        if not hasattr(context.raw_message, 'headers') or not context.raw_message.headers:
            msg = 'Raw message is missing headers.'
            raise ValueError(msg)
        if not hasattr(context.raw_message, 'body') or not context.raw_message.body:
            msg = 'Raw message is missing body.'
            raise ValueError(msg)

        encoding = context.raw_message.headers.get('Content-Transfer-Encoding', '').lower()
        if encoding == 'base64':
            try:
                base64.b64decode(context.raw_message.body, validate=True)
            except Exception as exc:
                msg = 'Invalid base64 encoding in message.'
                raise ValueError(msg) from exc


class CompositeValidation(ValidationComponent, LoggerMixin):
    """Composite validator to group multiple validators."""

    def __init__(self) -> None:
        """Initialize an empty validation component list."""
        self.components: list[ValidationComponent] = []

    def add(self, component: ValidationComponent) -> None:
        """Add a validation component."""
        self.components.append(component)

    def remove(self, component: ValidationComponent) -> None:
        """Remove a registered validation component."""
        if component not in self.components:
            msg = f'Validation component {component.__class__.__name__} is not registered.'
            raise ValueError(msg)
        self.components.remove(component)

    def validate(self, context: HttpBaseRequestContext) -> None:
        """Run all registered validation components in order."""
        for component in self.components:
            try:
                component.validate(context)
            except Exception as exc:
                self.logger.exception('Validation component %s failed', component.__class__.__name__)
                msg = f'{component.__class__.__name__}: {exc}'
                raise ValueError(msg) from exc


class CmpHttpRequestValidator(CompositeValidation):
    """Validator for CMP-specific HTTP requests."""

    def __init__(self) -> None:
        """Initialize the CMP HTTP validation chain."""
        super().__init__()
        self.add(TrustedProxyHeadersValidation())
        self.add(PayloadSizeValidation(max_payload_size=131072))
        self.add(ContentTypeValidation(expected_content_type='application/pkixcmp'))


class EstHttpRequestValidator(CompositeValidation):
    """Validator for EST-specific HTTP requests."""

    def __init__(self) -> None:
        """Initialize the EST HTTP validation chain."""
        super().__init__()
        self.add(TrustedProxyHeadersValidation())
        self.add(PayloadSizeValidation(max_payload_size=65536))
        self.add(ContentTypeValidation(expected_content_type='application/pkcs10'))
        self.add(AcceptHeaderValidation(allowed_content_types=['application/pkcs7-mime', '*/*']))
        self.add(ClientCertificateValidation())
        self.add(IntermediateCertificatesValidation())
        self.add(ContentTransferEncodingValidation())


class RestHttpRequestValidator(CompositeValidation):
    """Validator for REST API certificate enrollment requests."""

    def __init__(self) -> None:
        """Initialize the REST HTTP validation chain."""
        super().__init__()
        self.add(TrustedProxyHeadersValidation())
        self.add(PayloadSizeValidation(max_payload_size=65536))
        self.add(ContentTypeValidation(expected_content_type='application/json'))
        self.add(ClientCertificateValidation())
        self.add(IntermediateCertificatesValidation())
