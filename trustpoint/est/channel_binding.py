# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Verify RFC 7030 identity/POP linking against the request's TLS connection."""

from __future__ import annotations

import base64
import hmac
import ssl
from typing import TYPE_CHECKING

from cryptography import x509
from django.conf import settings
from pyasn1.codec.der import decoder  # type: ignore[import-untyped]
from pyasn1_modules import rfc2985, rfc2986  # type: ignore[import-untyped]

from request.request_validator.http_req import TrustedProxyHeadersValidation

if TYPE_CHECKING:
    from django.http import HttpRequest

    from request.request_context import EstCertificateRequestContext

CHALLENGE_PASSWORD_OID = '1.2.840.113549.1.9.7'  # noqa: S105 - PKCS#9 identifier, not a password.
_MAX_CHALLENGE_LENGTH = 255
_FINISHED_LENGTH = 12


def _csr_binding(csr: x509.CertificateSigningRequest) -> bytes | None:
    """Read exactly one DirectoryString value, rejecting duplicate attributes."""
    info, remainder = decoder.decode(csr.tbs_certrequest_bytes, asn1Spec=rfc2986.CertificationRequestInfo())
    if remainder:
        msg = 'Unexpected data after CSR request information.'
        raise ValueError(msg)
    challenges = [attribute for attribute in info['attributes'] if str(attribute['type']) == CHALLENGE_PASSWORD_OID]
    if not challenges:
        return None
    if len(challenges) != 1 or len(challenges[0]['values']) != 1:
        msg = 'EST challengePassword must contain exactly one attribute and one value.'
        raise ValueError(msg)
    value, remainder = decoder.decode(challenges[0]['values'][0].asOctets(), asn1Spec=rfc2985.DirectoryString())
    if remainder:
        msg = 'Unexpected data after EST challengePassword.'
        raise ValueError(msg)
    encoded = str(value.getComponent()).encode('ascii')
    if not 0 < len(encoded) <= _MAX_CHALLENGE_LENGTH:
        msg = 'EST challengePassword has an invalid length.'
        raise ValueError(msg)
    decoded = base64.b64decode(encoded, validate=True)
    if not decoded or base64.b64encode(decoded) != encoded:
        msg = 'EST challengePassword must use canonical Base64.'
        raise ValueError(msg)
    return encoded


def _connection_binding(request: HttpRequest) -> bytes:
    """Use a native TLS socket, or explicitly enabled trusted proxy assertions."""
    connection = request.META.get('werkzeug.socket')
    if isinstance(connection, ssl.SSLSocket):
        if not settings.DEVELOPMENT_ENV:
            msg = 'Native EST channel-binding verification is available only in the development server.'
            raise ValueError(msg)
        if connection.version() != 'TLSv1.2':
            msg = 'EST tls-unique channel binding requires TLS 1.2.'
            raise ValueError(msg)
        binding = connection.get_channel_binding('tls-unique')
        if not binding or len(binding) != _FINISHED_LENGTH:
            msg = 'TLS channel-binding data is unavailable for this connection.'
            raise ValueError(msg)
        return base64.b64encode(binding)

    if not settings.TRUSTPOINT_EST_TRUST_PROXY_CHANNEL_BINDING:
        msg = 'TLS channel-binding data is unavailable for this connection.'
        raise ValueError(msg)
    # This check also runs during HTTP validation, but keep the trust boundary
    # here so this function cannot accept untrusted assertions in isolation.
    TrustedProxyHeadersValidation().validate_request_peer(request)
    if (
        request.META.get('HTTP_X_EST_TLS_UNIQUE_SUPPORTED') != '1'
        or request.META.get('HTTP_X_EST_TLS_PROTOCOL') != 'TLSv1.2'
    ):
        msg = 'The TLS terminator cannot verify EST tls-unique on this connection.'
        raise ValueError(msg)
    encoded = str(request.META.get('HTTP_X_EST_TLS_UNIQUE') or '').encode('ascii')
    binding = base64.b64decode(encoded, validate=True)
    if len(binding) != _FINISHED_LENGTH or base64.b64encode(binding) != encoded:
        msg = 'The TLS terminator supplied invalid EST channel-binding data.'
        raise ValueError(msg)
    return encoded


def _verify_binding(context: EstCertificateRequestContext) -> bool:
    if not isinstance(context.cert_requested, x509.CertificateSigningRequest):
        msg = 'EST channel-binding verification requires a parsed CSR.'
        raise TypeError(msg)
    supplied = _csr_binding(context.cert_requested)
    if supplied is None:
        if settings.TRUSTPOINT_EST_REQUIRE_CHANNEL_BINDING:
            msg = 'TLS channel binding is required; include challengePassword in the CSR.'
            raise ValueError(msg)
        return False
    if context.raw_message is None:
        msg = 'The EST HTTP request is unavailable for channel-binding verification.'
        raise ValueError(msg)
    expected = _connection_binding(context.raw_message)
    if not hmac.compare_digest(supplied, expected):
        msg = 'EST challengePassword does not match the current TLS connection.'
        raise ValueError(msg)
    return True


def verify_est_channel_binding(context: EstCertificateRequestContext) -> None:
    """Reject an absent required binding or any supplied binding we cannot verify."""
    context.est_channel_binding_verified = False
    try:
        context.est_channel_binding_verified = _verify_binding(context)
    except TypeError:
        raise
    except Exception as exc:
        msg = 'EST TLS channel-binding verification failed.'
        context.error(msg, http_status=400)
        raise ValueError(msg) from exc
